#![no_std]

use asr::{signature::Signature, timer, timer::TimerState, watcher::{Watcher, Pair}, Address, Process};
use numtoa::NumToA;

const PROCESS_NAME: &str = "RAGE2.exe";

static AUTOSPLITTER: spinning_top::Spinlock<State> = spinning_top::const_spinlock(State {
    game: None,
    sigscans: None,
    watchers: WatcherList {
        loading_done: Watcher::new(),
        tracked_mission_id: Watcher::new(),
        start:Watcher::new()
    }
});

struct State {
    game: Option<ProcessInfo>,
    sigscans: Option<SigScanData>,
    watchers: WatcherList,
}

struct ProcessInfo {
    process: Process,
    main_module_base: Address,
    main_module_size: u64,
    fmod_module_base: Address,
    version: Version,

}
struct WatcherList {
    loading_done: Watcher<u8>,
    tracked_mission_id: Watcher<u32>,
    start: Watcher<u8>
}

impl State {
    fn attach_process() -> Option<ProcessInfo> {
        let process = Process::attach(PROCESS_NAME)?;
        let main_module_base = process.get_module_address(PROCESS_NAME).ok()?;
        let main_module_size = process.get_module_size(PROCESS_NAME).ok()?;
        let fmod_module_base = process.get_module_address("fmod_studio_F.dll").ok()?; //Needed for SteamUpdate2 Version, should still exists for other versions.
        let version = Version::from_module_size(main_module_size);

        Some (ProcessInfo { 
            process, 
            main_module_base,
            main_module_size,
            fmod_module_base,
            version,
        })
    }

    fn update(&mut self) {
        //Attach to game process if necessary
        if self.game.is_none() {
            self.game = State::attach_process();
        }
        let Some(game) = &self.game else { return };

        if !game.process.is_open() {
            self.game = None;
            self.sigscans = None;
            if timer::state() == TimerState::Running { timer::pause_game_time() }; //Pause the timer on game crash
            return;
        }

        //Perform the sigscans if necessary
        if self.sigscans.is_none() {
            self.sigscans = SigScanData::new(&game.process, game.main_module_base, game.main_module_size);
        }
        let Some(sigscans) = &self.sigscans else { return };

        let mut numtoa_buffer = [0u8; 20];
        timer::set_variable("sigscan_load_ui", sigscans.load_ui_base.0.numtoa_str(16, &mut numtoa_buffer));
        timer::set_variable("sigscan_loading_done_offset", sigscans.loading_done_offset.numtoa_str(16, &mut numtoa_buffer));
        timer::set_variable("sigscan_mission_manager", sigscans.mission_manager_base.0.numtoa_str(16, &mut numtoa_buffer));
        timer::set_variable("sigscan_tracked_mission_offset", sigscans.tracked_mission_offset.numtoa_str(16, &mut numtoa_buffer));

        //Update Watchers
        let Some(loading_done) = self.watchers.loading_done.update(game.process.read_pointer_path64(
            sigscans.load_ui_base.0, 
            &[0x0, sigscans.loading_done_offset]
        ).ok()) else { 
            timer::set_variable("watcher_loading_done", "Update Failed");
            return;
        };
        timer::set_variable_int("watcher_loading_done", loading_done.current);

        let Some(tracked_mission_id) = self.watchers.tracked_mission_id.update(game.process.read_pointer_path64(
            sigscans.mission_manager_base.0, 
            &[0x0, sigscans.tracked_mission_offset]
        ).ok()) else { 
            timer::set_variable("watcher_tracked_mission_id", "Update Failed");
            return;
        };
        timer::set_variable("watcher_tracked_mission_id", tracked_mission_id.current.numtoa_str(16, &mut numtoa_buffer));

        let start = if game.version == Version::SteamUpdate2 { //Copy-pasted from old asl. Janky, but works.
            self.watchers.start.update(game.process.read_pointer_path64(
                game.fmod_module_base.0,
                &[0x2C5520, 0x350, 0xA8, 0x80, 0x20, 0x19C]) 
                .ok()
            )
        } else {
            None
        };
        timer::set_variable_int("watcher_start", start.unwrap_or(&Pair{current:69, old: 69}).current);

        //AutoStart and loading logic
        match timer::state() {
            TimerState::NotRunning => {
                if State::should_start(loading_done, tracked_mission_id, start) {
                    timer::start();
                }
            },
            TimerState::Running => {
                if loading_done.current == 0 {
                    timer::pause_game_time();
                } else {
                    timer::resume_game_time();
                }
            },
            _ => {}
        };
            
    }

    fn should_start(loading_done: &Pair<u8>, tracked_mission_id: &Pair<u32>, start: Option<&Pair<u8>>) -> bool {
        if let Some(start_pair) = start { //SteamUpdate2 Any% Start
            if start_pair.current == 1 && start_pair.old == 0 {
                return true;
            }
        } else if tracked_mission_id.old == 0xDEADBEEF && tracked_mission_id.current == 0x759ED75A { //Other versions Any% Start
            return true;
        } else if tracked_mission_id.current == 0x4079F4A7 && loading_done.current == 1 && loading_done.old == 0 { //NG+ start
            return true;
        }

        false
    }
}

struct SigScanData {
    load_ui_base: Address,
    loading_done_offset: u64,
    mission_manager_base: Address,
    tracked_mission_offset: u64
}

impl SigScanData {
    fn new(process: &Process, module_base: Address, module_size: u64) -> Option<Self> {
        //Scan for cLoadUI->loading_done
        const SIG_LOAD_UI: Signature<14> = Signature::new("48 8B 1D ?? ?? ?? ?? 80 BB ?? 00 00 00 00");
        let mut scan: Address = SIG_LOAD_UI.scan_process_range(process, module_base, module_size)/* .and_then(SigScanData::validate_scan) */?;
        let load_ui: u64 = Self::read_offset_u32(process, scan.0, 3).unwrap();
        let loading_done_offset: u64 = process.read::<u32>(Address(scan.0 + 9)).ok()? as u64;

        //Scan for cMissionManager->mission_list
        const SIG_MISSION_MANAGER: Signature<24> = Signature::new("48 8B F1 48 8B 0D ?? ?? ?? ?? 48 8B 81 ?? ?? 00 00 48 8B 89 ?? ?? 00 00");
        scan = SIG_MISSION_MANAGER.scan_process_range(process, module_base, module_size)/* .and_then(SigScanData::validate_scan) */?;
        let mission_manager: u64 = Self::read_offset_u32(process, scan.0, 6).unwrap();
        let mission_list_offset: u64 = process.read::<u32>(Address(scan.0 + 13)).ok()? as u64;

        Some (Self {
            load_ui_base: Address(load_ui),
            loading_done_offset,
            mission_manager_base: Address(mission_manager),
            tracked_mission_offset: mission_list_offset + 0x20
        })
    }

    fn read_offset_u32(process: &Process, ptr: u64, sig_offset: u64) -> Option<u64> {
        let ptr = ptr + sig_offset;
        
        let offset:u64 = process.read::<u32>(Address(ptr)).ok()? as u64;

        Some(ptr + 0x4 + offset)
    }

    /*
    fn validate_scan(scan_address: Address) -> Option<Address> {
        match scan_address.0 {
            addr if addr < 0x1000 => None, // < 0x1000 means game not fully initialized and scan points to junk
            _ => Some(scan_address)
        }
    } 
    */
}

#[derive(PartialEq, Eq)]
enum Version {
    SteamUpdate2,
    EgsCurrentpatch,
    Unknown
}

impl Version {
    fn from_module_size(size:u64) -> Self {
        match size {
            52645888 => Self::SteamUpdate2,
            53592064 => Self::EgsCurrentpatch,
            _ => Self::Unknown
        }
    }
}

#[no_mangle]
pub extern "C" fn update() {
    AUTOSPLITTER.lock().update();
}

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
