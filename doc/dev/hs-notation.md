# Hidden services crypto keys notation

Text in quotes is the terminology used in `rend-spec-v3.txt`.

 * K_hsid:
   "Main (hidden service) identity key."

 * cred (or "hs_cred" where ambiguous):
   "Credential."

 * subcred (or "hs_cred" where ambiguous):
   "Subcredential."

 * rend_cookie:
   "Rendezvous cookie."

 * shared_rand:
   "Shared random value."

 * K_blind_id:

   "Blinded signing key."

 * K_desc_sign:

   "Descriptor signing key."

 * K_intro_auth:

   "Introduction point authentication key."
   (Sometimes referred to as `AUTH_KEY` eg rend-spec 3.1.1)

 * K_intro_enc:

   "Introduction point encryption key."

 * "K_desc_enc":

   "Descriptor encryption key."

 * "K_onion":

   "Onion key" (in `tor-spec`)

 * "KW", "hs_index", "hsdir_index"
   as in rend-spec-v3.

## Rust code notation

In Rust code we would write, for a variable, `k_hsid`,
or for a type `HsIdKey`.

Public keys are not marked with `Pub` so `DescSignKey`;
private keys are like `DescSignPrivKey`.

## Alternative if we are willing to have Rust types `K_...` and `N_...`.

I have chosen not to suggest the conventional `N_...` notation for the nonces,
because that translates poorly to Pascal-case type names.
`SubcredNonce` is awful.

If we don't mind underscores (and having to decorate types with `#[allow]`):

In docs and specs write
`N_cred`, `N_rend`, `N_subcred`, `N_shared`
(eliding the largely-vacuous nouns in favour of the cryptographer's N for Nonce).

Rust types `K_HsId`, `N_Subcred` etc.
