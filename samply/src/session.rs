use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

/// Session information stored in ~/.samply/session.json
/// This enables the query client to discover the running analysis server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Server URL including token prefix (e.g., "http://127.0.0.1:3000/abc123")
    pub server_url: String,
    /// Path to the profile file being served
    pub profile_path: String,
    /// Process ID of the server
    pub pid: u32,
    /// ISO 8601 timestamp when session was created
    pub started_at: String,
}

impl Session {
    /// Create a new session
    pub fn new(server_url: String, profile_path: String) -> Self {
        let now = chrono_lite_now();
        Self {
            server_url,
            profile_path,
            pid: std::process::id(),
            started_at: now,
        }
    }

    /// Get the path to the session file (~/.samply/session.json)
    pub fn session_file_path() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".samply").join("session.json")
    }

    /// Save session to the session file
    pub fn save(&self) -> io::Result<()> {
        let path = Self::session_file_path();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(&path, json)?;

        Ok(())
    }

    /// Load session from the session file
    pub fn load() -> io::Result<Session> {
        let path = Self::session_file_path();
        let content = fs::read_to_string(&path)?;
        let session: Session = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(session)
    }

    /// Remove the session file
    pub fn remove() -> io::Result<()> {
        let path = Self::session_file_path();
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Check if a session file exists
    pub fn exists() -> bool {
        Self::session_file_path().exists()
    }

    /// Check if the server process is still running
    #[cfg(unix)]
    pub fn is_server_alive(&self) -> bool {
        use std::process::Command;

        // On Unix, check if the process exists by sending signal 0
        Command::new("kill")
            .args(["-0", &self.pid.to_string()])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    pub fn is_server_alive(&self) -> bool {
        // On Windows, we'd need to use Windows API to check process status
        // For now, assume it's alive if the session file exists
        true
    }
}

/// Simple ISO 8601 timestamp without external crate
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();

    // Calculate date/time components (simplified, assumes UTC)
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simplified year/month/day calculation
    // This is approximate but good enough for our purposes
    let mut year = 1970;
    let mut remaining_days = days_since_epoch as i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let mut month = 1;
    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for days_in_month in days_in_months {
        if remaining_days < days_in_month as i64 {
            break;
        }
        remaining_days -= days_in_month as i64;
        month += 1;
    }

    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_roundtrip() {
        let session = Session::new(
            "http://127.0.0.1:3000/abc123".to_string(),
            "/path/to/profile.json".to_string(),
        );

        let json = serde_json::to_string(&session).unwrap();
        let parsed: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.server_url, parsed.server_url);
        assert_eq!(session.profile_path, parsed.profile_path);
        assert_eq!(session.pid, parsed.pid);
    }

    #[test]
    fn test_chrono_lite_now() {
        let timestamp = chrono_lite_now();
        // Should be in ISO 8601 format
        assert!(timestamp.contains("T"));
        assert!(timestamp.ends_with("Z"));
        assert_eq!(timestamp.len(), 20);
    }
}
