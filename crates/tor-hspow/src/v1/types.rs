//! Basic types used by the v1 client puzzle

use crate::v1::{SolutionByteArray, SolutionError, SolverInput, Verifier};
use tor_hscrypto::pk::HsBlindId;

/// Effort setting, a u32 value with linear scale
///
/// The numerical value is roughly the expected number of times we will
/// need to invoke the underlying solver (Equi-X) for the v1 proof-of-work
/// protocol to find a solution.
#[derive(
    derive_more::AsRef, derive_more::From, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd,
)]
pub struct Effort(u32);

/// Length of the random seed generated by servers and included in HsDir
pub const SEED_LEN: usize = 32;

/// The random portion of a challenge, distributed through HsDir
#[derive(derive_more::AsRef, derive_more::From, Debug, Clone, Eq, PartialEq)]
pub struct Seed([u8; SEED_LEN]);

impl Seed {
    /// Make a new [`SeedHead`] from a prefix of this seed
    pub fn head(&self) -> SeedHead {
        SeedHead(
            self.0[..SEED_HEAD_LEN]
                .try_into()
                .expect("slice length correct"),
        )
    }
}

/// Length of a seed prefix used to identify the entire seed
pub const SEED_HEAD_LEN: usize = 4;

/// A short seed prefix used in solutions to reference the complete seed
#[derive(derive_more::AsRef, derive_more::From, Debug, Clone, Copy, Eq, PartialEq)]
pub struct SeedHead([u8; SEED_HEAD_LEN]);

/// Length of the nonce value generated by clients and included in the solution
pub const NONCE_LEN: usize = 16;

/// Generated randomly by solvers and included in the solution
#[derive(derive_more::AsRef, derive_more::From, Debug, Clone, Eq, PartialEq)]
pub struct Nonce([u8; NONCE_LEN]);

/// One instance of this proof-of-work puzzle
///
/// Identified uniquely by the combination of onion service blinded Id key
/// plus a rotating seed chosen by the service.
#[derive(Debug, Clone)]
pub struct Instance {
    /// Blinded public Id key, binding this puzzle to a specific onion service
    service: HsBlindId,
    /// Seed value distributed in the HsDir by that service
    seed: Seed,
}

impl Instance {
    /// A new puzzle instance, wrapping a service Id and service-chosen seed
    pub fn new(service: HsBlindId, seed: Seed) -> Self {
        Self { service, seed }
    }

    /// Start preparing a particular [`SolverInput`] for this [`Instance`],
    /// by choosing an effort.
    ///
    /// All other settings are optional, accessed
    /// via builder methods on [`SolverInput`].
    pub fn with_effort(self, effort: Effort) -> SolverInput {
        SolverInput::new(self, effort)
    }

    /// Use this instance to construct a [`Verifier`], which can verify
    /// solutions and collect configuration options that control verification.
    pub fn verifier(self) -> Verifier {
        Verifier::new(self)
    }

    /// Get the [`HsBlindId`] identifying the service this puzzle is for.
    pub fn service(&self) -> &HsBlindId {
        &self.service
    }

    /// Get the rotating random [`Seed`] used in this puzzle instance.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }
}

/// One potential solution to some puzzle [`Instance`]
///
/// The existence of a [`Solution`] guarantees that the solution is well formed
/// (for example, the correct length, the correct order  in the Equi-X solution)
/// but it makes no guarantee to actually solve any specific puzzle instance.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Solution {
    /// Arbitrary value chosen by the solver to reach a valid solution
    ///
    /// Services are responsible for remembering used values to prevent replay.
    nonce: Nonce,

    /// The effort chosen by the client
    ///
    /// This is validated against the actual effort spent by the client using
    /// a combination of two checks:
    ///
    /// - We can ensure the effort value here was chosen prior to successfully
    ///   solving the Equi-X puzzle just by verifying the Equi-X proof.
    ///   Effort values are part of the [`crate::v1::challenge::Challenge`]
    ///   string the puzzle is constructed around.
    ///
    /// - We can ensure, on average, that the proper proportion of Equi-X
    ///   solutions have been discarded. The proof and challenge are hashed,
    ///   and the resulting digest is effectively a random variable that must
    ///   fit within a range inversely proportional to the effort. This test
    ///   happens in [`crate::v1::challenge::Challenge::check_effort`].
    effort: Effort,

    /// Prefix of the [`Seed`] used in this puzzle Instance
    ///
    /// A service will normally have two active [`Seed`] values at once.
    /// This prefix is sufficient to distinguish between them. (Services
    /// skip seeds which would have the same prefix as the last seed.)
    seed_head: SeedHead,

    /// Equi-X solution which claims to prove the above effort choice
    proof: equix::Solution,
}

impl Solution {
    /// Construct a new Solution around a well-formed [`equix::Solution`] proof.
    pub(super) fn new(
        nonce: Nonce,
        effort: Effort,
        seed_head: SeedHead,
        proof: equix::Solution,
    ) -> Self {
        Solution {
            nonce,
            effort,
            seed_head,
            proof,
        }
    }

    /// Try to build a [`Solution`] from an unvalidated [`SolutionByteArray`].
    ///
    /// This will either return a [`Solution`] or a [`SolutionError::Order`].
    pub fn try_from_bytes(
        nonce: Nonce,
        effort: Effort,
        seed_head: SeedHead,
        bytes: &SolutionByteArray,
    ) -> Result<Self, SolutionError> {
        Ok(Self::new(
            nonce,
            effort,
            seed_head,
            equix::Solution::try_from_bytes(bytes).map_err(|_| SolutionError::Order)?,
        ))
    }

    /// Get the winning [`Nonce`] value used in this solution
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Get the client-chosen and provable [`Effort`] value used in this solution
    pub fn effort(&self) -> Effort {
        self.effort
    }

    /// Get the [`SeedHead`] value identifying the puzzle this solution is for
    pub fn seed_head(&self) -> SeedHead {
        self.seed_head
    }

    /// Internal, access the [`equix::Solution`] backing the proof portion
    pub(super) fn proof(&self) -> &equix::Solution {
        &self.proof
    }

    /// Clone the proof portion of the solution in its canonical byte string format
    pub fn proof_to_bytes(&self) -> SolutionByteArray {
        self.proof.to_bytes()
    }
}
