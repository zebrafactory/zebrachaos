//! Encode and store /usr/share/doc, restore, double check.

use tempfile;
use zf_zebrachaos::{Item, Store, Tree};

fn main() -> std::io::Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let filename = tmp.path().join("chaos.data");
    let mut tree = Tree::new(Store::create(&filename)?);
    println!("created store in {:?}", tmp.path());

    let input = std::path::PathBuf::from("/usr/share/doc");
    if let Item::Dir(hash) = tree.snapshot(&input)? {
        println!("{hash}");
        let output = tempfile::TempDir::new()?;
        tree.restore(&hash, output.path())?;
        if let Item::Dir(hash2) = tree.snapshot(&output.path())? {
            assert_eq!(hash, hash2);
            println!("{hash2}");
        }
    }
    Ok(())
}
