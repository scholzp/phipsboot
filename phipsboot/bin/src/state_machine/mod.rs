pub mod pmc;
pub mod task;
pub mod task_id;

use crate::shared_mem_com::{SharedMemCommunicator, TeeCommand};
use crate::state_machine::task::execute_task;
use crate::state_machine::task_id::TaskId;
use log::info;

#[derive(Debug)]
pub struct StateMachine<S> {
    communicator: SharedMemCommunicator,
    _state: S,
}

#[derive(Debug, Default)]
pub struct StateInitialized;
#[derive(Debug, Default)]
pub struct StatePolling;
#[derive(Debug, Default)]
pub struct StateLocking;
#[derive(Debug, Default)]
pub struct StateExecuteApp;
#[derive(Debug, Default)]
pub struct StateUnlocking;
#[derive(Debug, Default)]
pub struct StateTransmitResult;

impl StateMachine<StateInitialized> {
    pub fn new(communicator: SharedMemCommunicator) -> Self {
        communicator.set_status(TeeCommand::TeeReady);
        communicator.set_task(TaskId::Unknown);
        StateMachine {
            communicator: communicator,
            _state: StateInitialized {},
        }
    }
}

impl From<StateMachine<StateInitialized>> for StateMachine<StatePolling> {
    fn from(mut m: StateMachine<StateInitialized>) -> StateMachine<StatePolling> {
        info!("Polling...");
        m.communicator.poll();
        info!("Received command");
        StateMachine {
            communicator: m.communicator,
            _state: StatePolling {},
        }
    }
}

impl From<StateMachine<StatePolling>> for StateMachine<StateLocking> {
    fn from(mut m: StateMachine<StatePolling>) -> StateMachine<StateLocking> {
        // pmc::setup_pmcs();
        StateMachine {
            communicator: m.communicator,
            _state: StateLocking {},
        }
    }
}

impl From<StateMachine<StateLocking>> for StateMachine<StateExecuteApp> {
    fn from(mut m: StateMachine<StateLocking>) -> StateMachine<StateExecuteApp> {
        // Execute task, collect results
        // info!("Execute task with ID {:#02x?}", m.communicator.get_task());
        execute_task(m.communicator.get_task(), &mut m.communicator);
        StateMachine {
            communicator: m.communicator,
            _state: StateExecuteApp {},
        }
    }
}

impl From<StateMachine<StateExecuteApp>> for StateMachine<StateUnlocking> {
    fn from(mut m: StateMachine<StateExecuteApp>) -> StateMachine<StateUnlocking> {
        // info!("Unlock TEE");
        // pmc::read_and_print_pmcs();
        StateMachine {
            communicator: m.communicator,
            _state: StateUnlocking {},
        }
    }
}

impl From<StateMachine<StateUnlocking>> for StateMachine<StateTransmitResult> {
    fn from(mut m: StateMachine<StateUnlocking>) -> StateMachine<StateTransmitResult> {
        // Copy results
        StateMachine {
            communicator: m.communicator,
            _state: StateTransmitResult {},
        }
    }
}

impl From<StateMachine<StateTransmitResult>> for StateMachine<StateInitialized> {
    fn from(mut m: StateMachine<StateTransmitResult>) -> StateMachine<StateInitialized> {
        // Change to initialized again; wait for commands
        StateMachine {
            communicator: m.communicator,
            _state: StateInitialized {},
        }
    }
}

pub fn run_state_machine(
    machine: StateMachine<StateInitialized>,
) -> StateMachine<StateInitialized> {
    let machine = StateMachine::<StatePolling>::from(machine);
    let machine = StateMachine::<StateLocking>::from(machine);
    let machine = StateMachine::<StateExecuteApp>::from(machine);
    let machine = StateMachine::<StateUnlocking>::from(machine);
    let machine = StateMachine::<StateTransmitResult>::from(machine);
    let machine = StateMachine::<StateInitialized>::from(machine);
    machine
}
