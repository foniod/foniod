use std::fs::read;
use std::io::Error;
use std::str::FromStr;

const SYS_CPU_ONLINE: &'static str = "/sys/devices/system/cpu/online";

/// Returns a list of online CPU IDs.
///
/// Error handling in this function is deliberately crashy
/// If the kernel returns with invalid data, it's OK to crash
/// If the kernel returns with different data format, it's OK to crash
/// If the user is trying to feed us invalid data, it's OK to crash
///
/// The only time an error is reported is when 
/// `/sys/devices/system/cpu/online` can't be opened.
pub fn get_online() -> Result<Vec<u8>, Error> {
    let cpus = unsafe { String::from_utf8_unchecked(read(SYS_CPU_ONLINE)?) };
    Ok(list_from_string(&cpus))
}

fn list_from_string(cpus: &str) -> Vec<u8> {
    let cpu_list = cpus.split(',').flat_map(|group| {
        let mut split = group.split('-');
        let start = u8::from_str(split.next().unwrap()).unwrap();
        let end = u8::from_str(split.next().unwrap()).unwrap();
        (start..=end)
    });
    cpu_list.collect()
}

mod test {
    use cpus::list_from_string;

    #[test]
    fn test() {
        assert_eq!(list_from_string("0-4"), vec![0, 1, 2, 3, 4]);
        assert_eq!(list_from_string("0-2,5-6"), vec![0, 1, 2, 5, 6]);
    }
}
