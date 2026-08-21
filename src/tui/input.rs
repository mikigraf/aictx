use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TextInput {
    value: String,
    cursor: usize,
    max_bytes: usize,
}

impl TextInput {
    pub(super) fn new(value: impl Into<String>, max_bytes: usize) -> Self {
        let value = value.into();
        let cursor = value.len();
        Self {
            value,
            cursor,
            max_bytes,
        }
    }

    pub(super) fn value(&self) -> &str {
        &self.value
    }

    pub(super) fn cursor_column(&self) -> usize {
        self.value[..self.cursor].chars().count()
    }

    pub(super) fn insert_char(&mut self, character: char) -> Result<()> {
        let mut encoded = [0_u8; 4];
        self.insert_str(character.encode_utf8(&mut encoded))
    }

    pub(super) fn insert_str(&mut self, value: &str) -> Result<()> {
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "text input contains a forbidden control character".to_owned(),
            ));
        }
        if self.value.len().saturating_add(value.len()) > self.max_bytes {
            return Err(Error::InvalidInput(format!(
                "text input is limited to {} bytes",
                self.max_bytes
            )));
        }
        self.value.insert_str(self.cursor, value);
        self.cursor += value.len();
        Ok(())
    }

    pub(super) fn backspace(&mut self) {
        let Some(previous) = self.value[..self.cursor].char_indices().next_back() else {
            return;
        };
        self.value.drain(previous.0..self.cursor);
        self.cursor = previous.0;
    }

    pub(super) fn delete(&mut self) {
        let Some(character) = self.value[self.cursor..].chars().next() else {
            return;
        };
        self.value
            .drain(self.cursor..self.cursor + character.len_utf8());
    }

    pub(super) fn move_left(&mut self) {
        if let Some(previous) = self.value[..self.cursor].char_indices().next_back() {
            self.cursor = previous.0;
        }
    }

    pub(super) fn move_right(&mut self) {
        if let Some(character) = self.value[self.cursor..].chars().next() {
            self.cursor += character.len_utf8();
        }
    }

    pub(super) fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub(super) fn move_end(&mut self) {
        self.cursor = self.value.len();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Choice {
    options: Vec<String>,
    selected: usize,
}

impl Choice {
    pub(super) fn new(options: Vec<String>, selected: usize) -> Self {
        debug_assert!(!options.is_empty());
        Self {
            selected: selected.min(options.len().saturating_sub(1)),
            options,
        }
    }

    pub(super) fn value(&self) -> &str {
        &self.options[self.selected]
    }

    pub(super) fn next(&mut self) {
        self.selected = (self.selected + 1) % self.options.len();
    }

    pub(super) fn previous(&mut self) {
        self.selected = self
            .selected
            .checked_sub(1)
            .unwrap_or(self.options.len() - 1);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum FieldValue {
    Text(TextInput),
    Choice(Choice),
}

#[cfg(test)]
mod tests {
    use super::TextInput;

    #[test]
    fn edits_at_unicode_boundaries_and_rejects_control_paste() {
        let mut input = TextInput::new("a🦀b", 32);
        input.move_left();
        input.backspace();
        assert_eq!(input.value(), "ab");
        assert!(input.insert_str("\nsecret").is_err());
        assert_eq!(input.value(), "ab");
    }

    #[test]
    fn paste_limit_is_measured_in_bytes_and_rejection_is_atomic() {
        let mut input = TextInput::new("", 4);
        input
            .insert_str("🦀")
            .unwrap_or_else(|error| panic!("four-byte character: {error}"));
        assert!(input.insert_str("x").is_err());
        assert_eq!(input.value(), "🦀");
    }
}
