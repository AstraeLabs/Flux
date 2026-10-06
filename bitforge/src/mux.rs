//! Container-mux vocabulary traits: [`Unpackage`] / [`Package`] and
//! [`Decrypt`] / [`Encrypt`].
//!
/// Parses a container input into an in-memory media representation.
pub trait Unpackage {
    /// Raw input accepted by `unpackage`.
    type Input;
    /// Media model produced by `unpackage`.
    type Media;
    /// Error type.
    type Error;

    /// Parses `input` into a media model.
    fn unpackage(&mut self, input: Self::Input) -> Result<Self::Media, Self::Error>;
}

/// Turns a media model into container output.
pub trait Package {
    /// Media model produced by `unpackage`.
    type Media;
    /// Packaged output.
    type Output;
    /// Error type.
    type Error;

    /// Packages `media` into output.
    fn package(&mut self, media: &Self::Media) -> Result<Self::Output, Self::Error>;
}

/// Removes encryption from a media model.
pub trait Decrypt {
    /// Media model produced by `unpackage`.
    type Media;
    /// Key material.
    type Keys;
    /// Error type.
    type Error;

    /// Decrypts `media` in place with `keys`.
    fn decrypt(&self, media: &mut Self::Media, keys: &Self::Keys) -> Result<(), Self::Error>;
}

/// Applies encryption to a media model.
pub trait Encrypt {
    /// Media model produced by `unpackage`.
    type Media;
    /// Encryption configuration.
    type Config;
    /// Error type.
    type Error;

    /// Encrypts `media` in place with `cfg`.
    fn encrypt(&mut self, media: &mut Self::Media, cfg: &Self::Config) -> Result<(), Self::Error>;
}
