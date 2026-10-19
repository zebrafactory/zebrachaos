use zf_zebrachaos::{DATA_MAX_LEN, HEADER, Info, ObjectError};

#[test]
fn test_info() {
    assert_eq!(Info::build(0, 0).unwrap_err(), ObjectError::DataLenBounds);
    assert_eq!(Info::build(0, 255).unwrap_err(), ObjectError::DataLenBounds);
    assert_eq!(
        Info::build(DATA_MAX_LEN + 1, 0).unwrap_err(),
        ObjectError::DataLenBounds
    );

    assert_eq!(
        Info::build(DATA_MAX_LEN + 1, 255).unwrap_err(),
        ObjectError::DataLenBounds
    );

    let info = Info::build(1, 0).unwrap();
    assert_eq!(info.value, 0);
    assert_eq!(info.data_len(), 1);
    assert_eq!(info.buf_len(), 1 + HEADER);
    assert_eq!(info.kind(), 0);

    let info = Info::build(1, 255).unwrap();
    assert_eq!(info.value, 255 << 24);
    assert_eq!(info.data_len(), 1);
    assert_eq!(info.buf_len(), 1 + HEADER);
    assert_eq!(info.kind(), 255);

    let info = Info::build(DATA_MAX_LEN, 0).unwrap();
    assert_eq!(info.value, (DATA_MAX_LEN - 1) as u32);
    assert_eq!(info.data_len(), DATA_MAX_LEN);
    assert_eq!(info.buf_len(), DATA_MAX_LEN + HEADER);
    assert_eq!(info.kind(), 0);

    let info = Info::build(DATA_MAX_LEN, 255).unwrap();
    assert_eq!(info.value, (DATA_MAX_LEN - 1) as u32 | 255 << 24);
    assert_eq!(info.data_len(), DATA_MAX_LEN);
    assert_eq!(info.buf_len(), DATA_MAX_LEN + HEADER);
    assert_eq!(info.kind(), 255);
}
