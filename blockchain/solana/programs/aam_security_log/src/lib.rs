//! AAM Security Log - Solana Program
//!
//! This program logs security events for Advanced Air Mobility (AAM) vehicles
//! to the Solana blockchain for tamper-evident audit trails.

use anchor_lang::prelude::*;

declare_id!("4KAuuJxmX2x2JD6d3F7jxyUqHNufxkYsaA38Rjbb9Ccr");

#[program]
pub mod aam_security_log {
    use super::*;

    /// Initialize the event counter (call once at program deployment)
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = 0;
        counter.authority = ctx.accounts.authority.key();
        counter.bump = ctx.bumps.counter;

        msg!("AAM Security Log initialized. Counter: {}", counter.count);
        Ok(())
    }

    /// Log a security event to the blockchain
    pub fn log_security_event(
        ctx: Context<LogEvent>,
        event_timestamp: i64,    // Detection timestamp (ms since epoch)
        event_type: u8,          // 1=GPS_SPOOF, 2=DOS, 3=MITM, 4=REPLAY, 5=GPS_JAM, 6=EVIL_TWIN
        confidence: u8,          // Detection confidence (0-100)
        vehicle_id: [u8; 32],    // SHA-256 hash of vehicle identifier
        data_hash: [u8; 32],     // SHA-256 hash of original event data
    ) -> Result<()> {
        // Validate inputs
        require!(event_type >= 1 && event_type <= 6, AAMError::InvalidEventType);
        require!(confidence <= 100, AAMError::InvalidConfidence);

        let clock = Clock::get()?;
        let event = &mut ctx.accounts.event;
        let counter = &mut ctx.accounts.counter;

        // Populate event data
        event.event_id = counter.count;
        event.block_timestamp = clock.unix_timestamp;
        event.slot = clock.slot;
        event.event_timestamp = event_timestamp;
        event.event_type = event_type;
        event.confidence = confidence;
        event.vehicle_id = vehicle_id;
        event.data_hash = data_hash;
        event.authority = ctx.accounts.authority.key();

        // Increment counter
        counter.count = counter.count.checked_add(1).ok_or(AAMError::CounterOverflow)?;

        // Emit event for indexing
        emit!(SecurityEventLogged {
            event_id: event.event_id,
            event_type,
            confidence,
            vehicle_id,
            slot: clock.slot,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "Security event logged: id={}, type={}, confidence={}, slot={}",
            event.event_id,
            event.event_type,
            event.confidence,
            clock.slot
        );

        Ok(())
    }

    /// Batch log multiple security events (more efficient for high throughput)
    pub fn log_batch_events(
        ctx: Context<LogBatch>,
        events: Vec<EventInput>,
    ) -> Result<()> {
        require!(!events.is_empty(), AAMError::EmptyBatch);
        require!(events.len() <= 10, AAMError::BatchTooLarge);

        let clock = Clock::get()?;
        let batch = &mut ctx.accounts.batch;
        let counter = &mut ctx.accounts.counter;

        batch.batch_id = counter.count;
        batch.event_count = events.len() as u8;
        batch.block_timestamp = clock.unix_timestamp;
        batch.slot = clock.slot;
        batch.authority = ctx.accounts.authority.key();

        // Store event hashes in batch
        for (i, event) in events.iter().enumerate() {
            require!(event.event_type >= 1 && event.event_type <= 6, AAMError::InvalidEventType);
            require!(event.confidence <= 100, AAMError::InvalidConfidence);

            if i < 10 {
                batch.event_hashes[i] = event.data_hash;
            }
        }

        counter.count = counter.count.checked_add(events.len() as u64).ok_or(AAMError::CounterOverflow)?;

        emit!(BatchEventsLogged {
            batch_id: batch.batch_id,
            event_count: batch.event_count,
            slot: clock.slot,
        });

        msg!("Batch logged: {} events, batch_id={}", events.len(), batch.batch_id);

        Ok(())
    }

    /// Query event count
    pub fn get_event_count(ctx: Context<GetCount>) -> Result<u64> {
        Ok(ctx.accounts.counter.count)
    }
}

// =============================================================================
// ACCOUNTS
// =============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + EventCounter::INIT_SPACE,
        seeds = [b"counter"],
        bump
    )]
    pub counter: Account<'info, EventCounter>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct LogEvent<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + SecurityEvent::INIT_SPACE
    )]
    pub event: Account<'info, SecurityEvent>,

    #[account(
        mut,
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, EventCounter>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct LogBatch<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + EventBatch::INIT_SPACE
    )]
    pub batch: Account<'info, EventBatch>,

    #[account(
        mut,
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, EventCounter>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetCount<'info> {
    #[account(
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, EventCounter>,
}

// =============================================================================
// STATE ACCOUNTS
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct EventCounter {
    pub count: u64,
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct SecurityEvent {
    pub event_id: u64,
    pub block_timestamp: i64,
    pub slot: u64,
    pub event_timestamp: i64,
    pub event_type: u8,
    pub confidence: u8,
    #[max_len(32)]
    pub vehicle_id: [u8; 32],
    #[max_len(32)]
    pub data_hash: [u8; 32],
    pub authority: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct EventBatch {
    pub batch_id: u64,
    pub event_count: u8,
    pub block_timestamp: i64,
    pub slot: u64,
    #[max_len(10, 32)]
    pub event_hashes: [[u8; 32]; 10],
    pub authority: Pubkey,
}

// =============================================================================
// INPUT TYPES
// =============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct EventInput {
    pub event_timestamp: i64,
    pub event_type: u8,
    pub confidence: u8,
    pub vehicle_id: [u8; 32],
    pub data_hash: [u8; 32],
}

// =============================================================================
// EVENTS
// =============================================================================

#[event]
pub struct SecurityEventLogged {
    pub event_id: u64,
    pub event_type: u8,
    pub confidence: u8,
    pub vehicle_id: [u8; 32],
    pub slot: u64,
    pub timestamp: i64,
}

#[event]
pub struct BatchEventsLogged {
    pub batch_id: u64,
    pub event_count: u8,
    pub slot: u64,
}

// =============================================================================
// ERRORS
// =============================================================================

#[error_code]
pub enum AAMError {
    #[msg("Invalid event type. Must be 1-6.")]
    InvalidEventType,

    #[msg("Invalid confidence. Must be 0-100.")]
    InvalidConfidence,

    #[msg("Counter overflow.")]
    CounterOverflow,

    #[msg("Batch cannot be empty.")]
    EmptyBatch,

    #[msg("Batch too large. Maximum 10 events.")]
    BatchTooLarge,
}
