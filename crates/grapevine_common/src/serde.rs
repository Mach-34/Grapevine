use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

// Serialize byte arrays longer than [u8; 32]
pub fn serialize_byte_buf<S, const N: usize>(
    data: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert the array to a slice and serialize it
    serializer.serialize_bytes(data)
}

// Deserialize byte arrays longer than [u8; 32]
pub fn deserialize_byte_buf<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct ByteArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte array of length 48")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut array = [0u8; N];
            for (i, byte) in array.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            Ok(array)
        }
    }

    deserializer.deserialize_byte_buf(ByteArrayVisitor)
}
