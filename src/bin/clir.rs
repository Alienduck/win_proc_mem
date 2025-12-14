// src/cli.rs

use clap::Parser;
use roblox_exp::memory_scanner;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pid: u32,

    #[arg(short, long)]
    value: Option<i32>,
}

fn main() {
    let args = Args::parse();

    println!("🎮 Roblox Exploiter - PID: {}", args.pid);

    // Créer l'exploiter
    let mut exploiter = match memory_scanner::get_process(args.pid) {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!("❌ Erreur: {:?}", e);
            return;
        }
    };

    // Exemple d'utilisation
    if let Some(value) = args.value {
        println!("🔍 Scanning pour la valeur: {}", value);

        // SCAN COMPLET - C'EST CE QUE VOUS VOULIEZ !
        match exploiter.full_memory_scan(value, "premier_scan") {
            Ok(addresses) => {
                println!("📋 Adresses trouvées: {}", addresses.len());

                // Afficher les 10 premières adresses
                for (i, addr) in addresses.iter().take(10).enumerate() {
                    println!("  {}. 0x{:x}", i + 1, addr);
                }

                if addresses.len() > 10 {
                    println!("  ... et {} autres", addresses.len() - 10);
                }
            }
            Err(e) => {
                eprintln!("❌ Erreur pendant le scan: {:?}", e);
            }
        }
    } else {
        println!("ℹ️  Utilisez --value <nombre> pour scanner une valeur spécifique");
        println!("💡 Exemple: --pid 1234 --value 100");
    }
}
