//! Extension traits for extracting custom objects from a [`bytes::Buf`]

use crate::{Error, FromBuf, Result};
use bytes::{Buf, Bytes};
use paste::paste;

macro_rules! get_primitive_checked {
    ($t:ty, $width:literal) => {
        paste! {
            #[doc = "This method wraps [`Buf::get_" $t "`] with a bounds check to ensure there are enough bytes remaining, without panicking."]
            fn [<get_ $t _checked>](&mut self) -> Result<$t> {
                if self.remaining() >= $width {
                    Ok(self.[<get_ $t>]())
                } else {
                    Err(Error::Truncated)
                }
            }
        }

    };
}

/// Extension trait for [`bytes::Buf`]
pub trait SafeBuf: Buf {
    /// Peek at a given number of bytes from the buffer, with a check to ensure there are enough remaining
    ///
    /// Use this version when you know the array length at compile time. Otherwise use [`BufExt::peek_checked`].
    ///
    /// # Errors
    ///
    /// This method will return an error if the number of bytes remaining in the buffer is insufficent
    fn peek_checked_const<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.remaining() < N {
            Err(Error::Truncated)
        } else {
            let mut bytes = [0_u8; N];
            self.copy_to_slice(&mut bytes);
            Ok(bytes)
        }
    }

    /// Take a given number of bytes from the buffer, with a check to ensure there are enough remaining
    ///
    /// Use this version when you know the array length at compile time. Otherwise use [`BufExt::take_checked`].
    ///
    /// # Errors
    ///
    /// This method will return an error if the number of bytes remaining in the buffer is insufficent
    fn take_checked_const<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.peek_checked_const()?;
        self.advance(N);
        Ok(bytes)
    }

    /// Peek at a given number of bytes from the buffer, with a check to ensure there are enough remaining
    ///
    /// If you know the array length at compile time. Otherwise use [`BufExt::peek_checked_const`].
    ///
    /// # Errors
    ///
    /// This method will return an error if the number of bytes remaining in the buffer is insufficent
    fn peek_checked(&mut self, len: usize) -> Result<Bytes> {
        if self.remaining() < len {
            Err(Error::Truncated)
        } else {
            Ok(self.copy_to_bytes(len))
        }
    }

    /// Take a given number of bytes from the buffer, with a check to ensure there are enough remaining
    ///
    /// If you know the array length at compile time. Otherwise use [`BufExt::take_checked_const`].
    ///
    /// # Errors
    ///
    /// This method will return an error if the number of bytes remaining in the buffer is insufficent
    fn take_checked(&mut self, len: usize) -> Result<Bytes> {
        let bytes = self.peek_checked(len)?;
        self.advance(len);
        Ok(bytes)
    }

    /// Read a custom object from a buffer
    ///
    /// # Errors
    ///
    /// This method will return an error if the number of bytes remaining in the buffer is insufficent, or if the type cannot be parsed from the bytes.
    fn extract<T>(&mut self) -> Result<T>
    where
        T: FromBuf,
    {
        T::from_buf(self)
    }

    /// Check whether this reader is exhausted (out of bytes).
    ///
    /// # Errors
    ///
    /// this method will return [`Error::ExtraneousBytes`] if there are bytes left in the buffer.
    fn should_be_exhausted(&self) -> Result<()> {
        if self.has_remaining() {
            Err(Error::ExtraneousBytes)
        } else {
            Ok(())
        }
    }

    get_primitive_checked!(u8, 1);
    get_primitive_checked!(u16, 2);
    get_primitive_checked!(u32, 4);
}

impl<T> SafeBuf for T where T: Buf {}
