//! Linux fork / RLIMIT yoklaması. Tek iş parçacıklı süreç; libtest havuzu yoktur.
//!
//! Windows ve diğer platformlarda yoklama hemen başarılı döner. Gerçek `fork`
//! ve `RLIMIT_MEMLOCK` denetimi yalnızca Linux ikilisinde çalışır.

fn main() {
    if let Err(err) = nexus_ephemera_memlock::run_fork_assurance_probe() {
        eprintln!("fork assurance: {err}");
        std::process::exit(1);
    }
}
