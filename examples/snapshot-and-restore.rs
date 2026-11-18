//! Encode and store /usr/share/doc, restore, double check.

use tempfile;
use zf_zebrachaos::{Item, Repository, Store};

fn main() -> std::io::Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let filename = tmp.path().join("chaos.data");
    let mut repository = Repository::new(Store::create(&filename)?);

    println!("created store in {filename:?}");

    let input = std::path::PathBuf::from("/usr/share/doc");
    if let Item::Dir(hash) = repository.snapshot(&input)? {
        println!("{hash}");
        let output = tempfile::TempDir::new()?;
        println!("Restoring Tree in {:?}", output.path());
        repository.restore(&hash, output.path())?;
        if let Item::Dir(hash2) = repository.snapshot(&output.path())? {
            assert_eq!(hash, hash2);
            println!("{hash2}");
        }
    }
    let store = repository.into_store();
    println!("data_total: {}", store.data_total());
    println!("total: {}", store.total());
    println!("count: {}", store.count());
    Ok(())
}
