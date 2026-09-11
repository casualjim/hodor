//! SNI extraction from TLS `ClientHello` bytes.

/// Max bytes buffered while waiting for a complete `ClientHello`.
pub const MAX_HELLO: usize = 16 * 1024;

/// Extract the SNI hostname from a TLS `ClientHello` message.
///
/// `data` should contain at least the TLS record header and the `ClientHello`.
/// Returns the lowercased name with any trailing dot trimmed, or `None` when
/// the data is not a `ClientHello` or carries no SNI.
pub fn extract_sni(data: &[u8]) -> Option<String> {
  // TLS record header: type(1) + version(2) + length(2).
  if data.len() < 5 {
    return None;
  }
  if data[0] != 0x16 {
    return None; // Not a Handshake record.
  }

  let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
  let record_end = 5usize.checked_add(record_len)?;
  let record = data.get(5..record_end)?;

  // Handshake header: type(1) + length(3).
  if record.first() != Some(&0x01) {
    return None; // Not ClientHello.
  }
  if record.len() < 4 {
    return None;
  }
  let hs_len = (record[1] as usize) << 16 | (record[2] as usize) << 8 | (record[3] as usize);
  let hello_end = 4usize.checked_add(hs_len)?;
  let hello = record.get(4..hello_end)?;

  // ClientHello: version(2) + random(32) = 34 bytes.
  if hello.len() < 34 {
    return None;
  }
  let mut pos = 34;

  // Session ID.
  let session_id_len = *hello.get(pos)? as usize;
  pos += 1 + session_id_len;

  // Cipher suites.
  if pos + 2 > hello.len() {
    return None;
  }
  let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
  pos += 2 + cipher_suites_len;

  // Compression methods.
  let comp_len = *hello.get(pos)? as usize;
  pos += 1 + comp_len;

  // Extensions.
  if pos + 2 > hello.len() {
    return None;
  }
  let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
  pos += 2;

  let extensions_end = pos.checked_add(extensions_len)?;
  while pos + 4 <= extensions_end && pos + 4 <= hello.len() {
    let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
    let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
    pos += 4;

    if ext_type == 0x0000 {
      // SNI extension.
      let ext_end = pos.checked_add(ext_len)?;
      let name = parse_sni_extension(hello.get(pos..ext_end)?)?;
      let name = name.trim_end_matches('.').to_ascii_lowercase();
      return (!name.is_empty()).then_some(name);
    }

    pos = pos.checked_add(ext_len)?;
  }

  None
}

/// Parse the SNI extension data to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
  // ServerNameList: length(2) + entries.
  if data.len() < 2 {
    return None;
  }
  let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
  let list = data.get(2..2 + list_len)?;

  let mut pos = 0;
  while pos + 3 <= list.len() {
    let name_type = list[pos];
    let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
    pos += 3;

    if name_type == 0x00 {
      // HostName.
      let name_bytes = list.get(pos..pos + name_len)?;
      return String::from_utf8(name_bytes.to_vec()).ok();
    }

    pos += name_len;
  }

  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[expect(clippy::cast_possible_truncation, reason = "test builds tiny hellos")]
  fn client_hello_for(name: &str) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // version
    hello.extend_from_slice(&[0xabu8; 32]); // random
    hello.push(0); // session id len
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    hello.extend_from_slice(&[0x01, 0x00]); // compression
    let mut sni = Vec::new();
    sni.push(0x00); // HostName
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name.as_bytes());
    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x00]); // extension type SNI
    exts.extend_from_slice(&((sni.len() + 2) as u16).to_be_bytes());
    exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni);
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16 + 4).to_be_bytes());
    record.push(0x01); // ClientHello
    let len = hello.len() as u32;
    record.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    record.extend_from_slice(&hello);
    record
  }

  #[test]
  fn extracts_and_normalizes_sni() {
    let hello = client_hello_for("Example.COM.");
    assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
  }

  #[test]
  fn rejects_non_client_hello() {
    assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
    assert_eq!(extract_sni(&[0x16, 0x03]), None);
    // application-data record, not handshake
    assert_eq!(extract_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]), None);
    // truncated hello
    let mut hello = client_hello_for("example.com");
    hello.truncate(30);
    assert_eq!(extract_sni(&hello), None);
  }

  #[test]
  fn rejects_empty_sni() {
    assert_eq!(extract_sni(&client_hello_for("")), None);
    assert_eq!(extract_sni(&client_hello_for(".")), None);
  }
}
