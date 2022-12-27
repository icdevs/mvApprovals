import SHA256 "mo:crypto/SHA/SHA256";
import AccountIdentifier "mo:principalx/AccountIdentifier";
import Time "mo:base/Time";
import Blob "mo:base/Blob";
import Int "mo:base/Int";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Conversion "mo:candy/conversion";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Result "mo:base/Result";
import DFXTypes "dfxtypes";
import ICRC1Types "icrc1types";

///////////////////////
// Minimum Viable Approval Canister
// --------------------------
// The minimum viable approval canister is a conceptual canister that can provide
// safe approval and transfer from functionality to any ledger canister without havint
// to burden the main ledger canister with additional state recores or by
// complicating the ledger logic with additional logic.
//
// This canister can be blackholed and provide secure approal and
// transfer from functionality for any IC Ledger or ICRC-1 based token.
// A service can deploy its own canister or the token itself could deploy
// a canonical transfer from / approval canister.
//
// This canister maintains no state and should be rather small in footprint.
//
// One could add some state to maintain active approvals and refund
// them via timers after the lock has expired, but we've left that implementation
// out for simplicity.
//
// User can initiate refunds by knowing the to/from principals and the
// lock_reciept that should be passed as part of the memo in the approval canister.
// ICRC-1 transactions are a bit more transparent for this case as the to and from
// principals are encoded in the ledger.  For other ledgers the To principal is
// hashed and provided in the first 32 bits of the memo.  Since users should
// know their own from principal and address and should know their own address,
// they should be able to find any "lost" transactions and request refunds after
// the lock has expired.
//
// For ICRC-1 Canisters where the to and from are known, a simple ledger
// watcher could be created that could attempt to refund any transactions
// from a remote canister by watching the ledger and waiting for the
// expirations to occur.
//
// One could also add this functionality to the ledger it self in a way
// that supports ICRC-2 and avoid having to store additional data with a
// few restrictions on ICRC-2: 1. Locks are not optional and 2. Lock_reciept
// needs to be provided with the transfer from fucntion.
//
// One could remove the lock_receipt from this and strictly go on subaccounts
// based on to and from princpals, but one would then create a race conditions
// where a service could expect an approval to be there while an approver
// removes the funds from under them.  This is safe from a double spend perspecive
// as the service should get an insufficent funds error, but they will need to
// handle it gracefully.

actor class mvApproval() = this {
  type Locks = {
    #minutes : Nat;
    #hours : Nat;
    #days : Nat;
    #years : Nat;
    #seconds : Nat;
    #utc_timestamp : Nat;
    //Should be seconds from Jan 1, 1970;
  };

  type ApprovalAccountRequest = {
    from_principal : Principal;
    to_principal : Principal;
    lock : Locks;
  };

  type ApprovalAccountResponse = {
    //sender must include one extra fee for transfering full amount.
    account : {
      principal : Principal;
      sub_account : [Nat8];
    };
    account_ledger_text : Text;
    account_icrc1_text : Text;
    lock_receipt : Nat32;
    memo : Nat64;
    memo_blob : Blob;
  };

  type TransferFromRequest = {
    to : {
      owner : Principal;
      subaccount : ?[Nat8];
    };
    from : {
      owner : Principal;
      //because the dapp is calling the transferFrom we expect they know the users's princpal.
      subaccount : ?[Nat8];
    };
    standard : {
      #ledger;
      #icrc1;
    };
    fee : Nat;
    canister : Principal;
    lock_receipt : Nat32;
    amount : Nat;
  };

  type TransferFromResponse = Result.Result<{ #ledger : DFXTransferResult; #icrc1 : ICRC1TransferResult }, Text>;

  type DFXTransferResult = Result.Result<Nat64, DFXTypes.TransferError>;

  type ICRC1TransferResult = Result.Result<Nat, ICRC1Types.TransferError>;

  type AllowanceRequest = {
    to : {
      owner : Principal;
      subaccount : ?[Nat8];
    };
    from : {
      owner : Principal;
      //because the dapp is calling the transferFrom we expect they know the users's princpal.
      subaccount : ?[Nat8];
    };
    standard : {
      #ledger;
      #icrc1;
    };
    canister : Principal;
    lock_receipt : Nat32;
  };

  type AllowanceResponse = {
    to : {
      owner : Principal;
      subaccount : ?[Nat8];
    };
    from : {
      owner : Principal;
      //because the dapp is calling the transferFrom we expect they know the users's princpal.
      subaccount : ?[Nat8];
    };
    amount : Nat;
    lock_receipt : Nat32;
  };

  private func calc_hash(
    from_principal : Principal,
    to_principal : Principal,
    lock_receipt : Nat32,
  ) : [Nat8] {
    let h = SHA256.New();
    h.write(Blob.toArray(Text.encodeUtf8("com.icdevs.approval")));
    h.write(Blob.toArray(Text.encodeUtf8("com.icdevs.approval.from")));
    h.write(Blob.toArray(Principal.toBlob(from_principal)));
    h.write(Blob.toArray(Text.encodeUtf8("com.icdevs.approval.to")));
    h.write(Blob.toArray(Principal.toBlob(to_principal)));
    h.write(Blob.toArray(Text.encodeUtf8("com.icdevs.approval.lock")));
    h.write(Blob.toArray(Conversion.valueToBlob(#Nat32(lock_receipt))));
    let hash = h.sum([]);
    hash;
  };

  private func calc_memo(to_principal : Principal, lock_receipt : Nat32) : Nat64 {
    let h = Principal.hash(to_principal);
    //this is an unsafe 32 bit hash, but we don't use it for security, only identification of memos
    var base = (Nat64.fromNat(Nat32.toNat(h)) << 32);
    base += (Nat64.fromNat(Nat32.toNat(lock_receipt)));
    base;
  };

  // Approvals
  // ---------
  // Instead of an approval function we have an approval query that returns
  // a ledger account controled by this canister.  User can create an approval
  // by sending items to this account.
  // ---------

  public query func getApprovalAccount(request : ApprovalAccountRequest) : async ApprovalAccountResponse {

    let now = Int.abs(Time.now());

    let stamp : Nat = switch (request.lock) {
      case (#minutes(val)) {
        (val * 1_000_000_000 * 60) + now;
      };
      case (#hours(val)) {
        (val * 1_000_000_000 * 60 * 60) + now;
      };
      case (#days(val)) {
        (val * 1_000_000_000 * 60 * 60 * 24) + now;
      };
      case (#years(val)) {
        (val * 1_000_000_000 * 60 * 60 * 24 * 365) + now;
      };
      case (#seconds(val)) {
        (val * 1_000_000_000) + now;
      };
      case (#utc_timestamp(val)) {
        val;
      };
    };

    let lock_receipt : Nat32 = Conversion.valueToNat32(#Nat(stamp / 1000000000));

    let hash = calc_hash(
      request.from_principal,
      request.to_principal,
      lock_receipt,
    );

    let account_raw = AccountIdentifier.fromPrincipal(
      Principal.fromActor(this),
      ?hash,
    );
    let account_text = AccountIdentifier.toText(account_raw);

    let memo = calc_memo(request.from_principal, lock_receipt);

    return {
      account = {
        principal = Principal.fromActor(this);
        sub_account = hash;
      };
      account_ledger_text = account_text;
      //implement crc32 capitalization check
      account_icrc1_text = Principal.toText(Principal.fromActor(this)) # ":" # Conversion.valueToText(#Bytes(#frozen(hash)));
      lock_receipt = lock_receipt;
      memo = memo;
      memo_blob = Conversion.valueToBlob(#Nat64(memo));
    };
  };

  //Allowance
  // --------
  // An allowance function is not necissary as you can just query the ledger for
  // a balance of the approval account.  This would just be a pass through query
  // and since there are not intercanister queries it would need to be an update call
  //---------

  private func dfx_send(request : TransferFromRequest, destination : Blob) : async * DFXTransferResult {
    let dfx : DFXTypes.Service = actor (Principal.toText(request.canister));
    let result = await dfx.transfer({ to = destination; fee = { e8s = Nat64.fromNat(request.fee) }; memo = calc_memo(request.from.owner, request.lock_receipt); from_subaccount = ?calc_hash(request.from.owner, request.to.owner, request.lock_receipt); created_at_time = ?{ timestamp_nanos = Nat64.fromNat(Int.abs(Time.now())) }; amount = { e8s = Nat64.fromNat(request.amount) } });
    switch (result) {
      case (#Ok(BlockIndex)) return #ok(BlockIndex);
      case (#Err(TransferError)) return #err(TransferError);
    };
  };

  private func icrc1_send(
    request : TransferFromRequest,
    destination : ICRC1Types.Account,
  ) : async * ICRC1TransferResult {
    let icrc1 : ICRC1Types.FullInterface = actor (Principal.toText(request.canister));
    let result = await icrc1.icrc1_transfer({ 
      to = destination; 
      fee = ?request.fee; 
      memo = ?Conversion.valueToBlob(#Nat64(calc_memo(request.from.owner, request.lock_receipt))); 
      from_subaccount = ?Blob.fromArray(calc_hash(request.from.owner, request.to.owner, request.lock_receipt)); 
      created_at_time = ?Nat64.fromNat(Int.abs(Time.now())); 
      amount = request.amount });
    switch (result) {
      case (#ok(BlockIndex)) return #ok(BlockIndex);
      case (#err(TransferError)) return #err(TransferError);
    };
  };

  // Transfer From
  // ------------
  // Allows the spender to move tokens from the approval account to the
  // spender's account.  To attempt to provide atomicity gurantees, the approver
  // cannot refund the funds back to their account until after the lock expires

  public shared (msg) func transferFrom(request : TransferFromRequest) : async TransferFromResponse {
    //check that the caller is the to principal
    if (request.to.owner == msg.caller) {
      if (request.to.owner == request.from.owner) {
        return #err("no self calls allowed");
      };
      if (request.lock_receipt > Nat32.fromNat(Int.abs(Time.now() / 1000000000))) {
        return #err("lock past expiration");
      };
    } else {
      return #err("must be called by recipient");
    };

    switch (request.standard) {
      case (#ledger) return #ok(#ledger(await * dfx_send(request, 
        Blob.fromArray(AccountIdentifier.fromPrincipal(request.to.owner, request.to.subaccount)))));
      case (#icrc1) return #ok(#icrc1(await * icrc1_send(request, 
        { 
          owner = request.to.owner; 
          subaccount = switch (request.to.subaccount) { case (null) { null }; case (?val) { ?Blob.fromArray(val) } } })));
    };
  };

  public shared (msg) func refund(request : TransferFromRequest) : async TransferFromResponse {
    //anyone can refund after the lock has expired
    if (request.lock_receipt <= Nat32.fromNat(Int.abs(Time.now() / 1000000000))) {
      //we could allow the to account to refund themselves before the lock period ends
      //but it would reduce gurantees to the spending service that the item was there.
      return #err("lock has not expired");
    };

    switch (request.standard) {
      case (#ledger) return #ok(#ledger(await * dfx_send(request, Blob.fromArray(AccountIdentifier.fromPrincipal(request.from.owner, request.from.subaccount)))));
      case (#icrc1) return #ok(#icrc1(await * icrc1_send(request, { owner = request.from.owner; subaccount = switch (request.from.subaccount) { case (null) { null }; case (?val) { ?Blob.fromArray(val) } } })));
    };
  };
};
