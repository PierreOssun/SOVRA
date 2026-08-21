//! The backend selection seam: which `PartyRunner` implementation this
//! cosigner drives. The entire sl-dkls23 → 0xCarbon migration lands on the
//! handlers as this one alias — a future backend swap touches this line and
//! nothing else in the crate.

/// The active MPC backend. Stateless (a ZST): handlers construct it with
/// `ActiveRunner::default()`.
pub type ActiveRunner = sovra_mpc_dkls23_carbon::CarbonRunner;
