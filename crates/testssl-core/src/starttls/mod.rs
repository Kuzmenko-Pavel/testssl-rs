//! STARTTLS protocol negotiation

pub mod ftp;
pub mod imap;
pub mod irc;
pub mod ldap;
pub mod lmtp;
pub mod mysql;
pub mod nntp;
pub mod pop3;
pub mod postgres;
pub mod sieve;
pub mod smtp;
pub mod xmpp;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::tls::socket::TlsSocket;

/// STARTTLS protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StarttlsProtocol {
    Smtp,
    Imap,
    Pop3,
    Ftp,
    Ldap,
    Xmpp,
    XmppServer,
    Postgres,
    Mysql,
    Nntp,
    Irc,
    Sieve,
    Lmtp,
}

impl StarttlsProtocol {
    pub fn default_port(self) -> u16 {
        match self {
            StarttlsProtocol::Smtp => 25,
            StarttlsProtocol::Imap => 143,
            StarttlsProtocol::Pop3 => 110,
            StarttlsProtocol::Ftp => 21,
            StarttlsProtocol::Ldap => 389,
            StarttlsProtocol::Xmpp | StarttlsProtocol::XmppServer => 5222,
            StarttlsProtocol::Postgres => 5432,
            StarttlsProtocol::Mysql => 3306,
            StarttlsProtocol::Nntp => 119,
            StarttlsProtocol::Irc => 6667,
            StarttlsProtocol::Sieve => 4190,
            StarttlsProtocol::Lmtp => 24,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            StarttlsProtocol::Smtp => "smtp",
            StarttlsProtocol::Imap => "imap",
            StarttlsProtocol::Pop3 => "pop3",
            StarttlsProtocol::Ftp => "ftp",
            StarttlsProtocol::Ldap => "ldap",
            StarttlsProtocol::Xmpp => "xmpp",
            StarttlsProtocol::XmppServer => "xmpp-server",
            StarttlsProtocol::Postgres => "postgres",
            StarttlsProtocol::Mysql => "mysql",
            StarttlsProtocol::Nntp => "nntp",
            StarttlsProtocol::Irc => "irc",
            StarttlsProtocol::Sieve => "sieve",
            StarttlsProtocol::Lmtp => "lmtp",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "smtp" | "smtps" => Some(StarttlsProtocol::Smtp),
            "imap" | "imaps" => Some(StarttlsProtocol::Imap),
            "pop3" | "pop3s" => Some(StarttlsProtocol::Pop3),
            "ftp" | "ftps" => Some(StarttlsProtocol::Ftp),
            "ldap" | "ldaps" => Some(StarttlsProtocol::Ldap),
            "xmpp" => Some(StarttlsProtocol::Xmpp),
            "xmpp-server" => Some(StarttlsProtocol::XmppServer),
            "postgres" | "postgresql" => Some(StarttlsProtocol::Postgres),
            "mysql" => Some(StarttlsProtocol::Mysql),
            "nntp" => Some(StarttlsProtocol::Nntp),
            "irc" => Some(StarttlsProtocol::Irc),
            "sieve" => Some(StarttlsProtocol::Sieve),
            "lmtp" => Some(StarttlsProtocol::Lmtp),
            _ => None,
        }
    }

    /// Perform STARTTLS negotiation on the socket
    pub async fn negotiate(&self, socket: &mut TlsSocket) -> Result<()> {
        match self {
            StarttlsProtocol::Smtp => smtp::negotiate(socket).await,
            StarttlsProtocol::Imap => imap::negotiate(socket).await,
            StarttlsProtocol::Pop3 => pop3::negotiate(socket).await,
            StarttlsProtocol::Ftp => ftp::negotiate(socket).await,
            StarttlsProtocol::Ldap => ldap::negotiate(socket).await,
            StarttlsProtocol::Xmpp | StarttlsProtocol::XmppServer => xmpp::negotiate(socket).await,
            StarttlsProtocol::Postgres => postgres::negotiate(socket).await,
            StarttlsProtocol::Mysql => mysql::negotiate(socket).await,
            StarttlsProtocol::Nntp => nntp::negotiate(socket).await,
            StarttlsProtocol::Sieve => sieve::negotiate(socket).await,
            StarttlsProtocol::Lmtp => lmtp::negotiate(socket).await,
            StarttlsProtocol::Irc => irc::negotiate(socket).await,
        }
    }
}
