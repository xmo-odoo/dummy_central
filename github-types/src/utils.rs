use serde::Deserialize;

pub fn unset<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    // if we find the field at all, wrap it in a `Some`, this way:
    // - unset => None
    // - set to null => Some(None)
    // - set to a value => Some(Some(v))
    Ok(Some(<T>::deserialize(de)?))
}
