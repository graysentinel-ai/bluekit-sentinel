# Security Policy

## ⚠️ Authorized Use Only

BlueKit Sentinel is a **defensive security tool** intended for:

- Authorized penetration testing
- Incident response on systems you own or administer
- Security research in isolated lab environments
- Threat hunting in your own environment

**You must have explicit written authorization** to run this tool against
any system you do not personally own or administer.

Unauthorized use of this tool — including but not limited to:
- Scanning networks without permission
- Capturing packets on networks you do not own
- Accessing authentication logs on systems you do not administer
- Monitoring users without their consent

— may violate computer fraud and wiretap laws in your jurisdiction, including:

- **India**: Information Technology Act 2000 (§43, §66, §66C, §66F)
- **USA**: Computer Fraud and Abuse Act (CFAA), Wiretap Act, ECPA
- **UK**: Computer Misuse Act 1990
- **EU**: GDPR, Network and Information Security Directive
- **Other jurisdictions**: equivalent laws apply

**Graysentinel Cyber Defence Lab accepts no liability for misuse of this tool.**

The authors and copyright holders are not responsible for any damage,
legal consequences, or harm caused by misuse.

## 📋 Before You Run

Before executing BlueKit Sentinel, confirm:

- [ ] You own or have written authorization for the target system
- [ ] You understand what data will be captured
- [ ] You have permission to access `/var/log/auth.log` (if applicable)
- [ ] You have permission to capture network packets (if using `--pcap`)
- [ ] Your use complies with your organization's acceptable-use policy
- [ ] You have read and understood this document

## 🛡️ Reporting Security Vulnerabilities

**Please do NOT open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in BlueKit Sentinel, please email:

**📧 graysentinel.ai@gmail.com**

Include in your report:

1. **Description** of the vulnerability
2. **Reproduction steps** (as detailed as possible)
3. **Potential impact** assessment
4. **Suggested fix** (if you have one)
5. **Your name / handle** (optional, for credit)

### What to expect

- **Acknowledgment** within 72 hours
- **Status update** within 7 days
- **Credit** in the fix commit (if you want)
- **Coordinated disclosure** — we will work with you on a timeline

### Please do NOT

- Open public issues for security bugs
- Test on systems you do not own
- Access, modify, or delete data that is not yours
- Pivot to other systems during testing
- Share vulnerability details publicly before a fix is released

## 🔒 Supported Versions

| Version | Status | Security Updates |
|---------|--------|------------------|
| 1.0.x   | ✅ Current | Yes — security fixes will be released |
| < 1.0   | ❌ Not released | N/A |

## 🚨 Known Limitations

BlueKit Sentinel is designed to be **safe and read-only**, but be aware:

- **Packet capture** (`--pcap`) captures raw network traffic — treat captured data as sensitive
- **FIM** (file integrity monitoring) reads `/etc/shadow` and similar files — requires root
- **Auth monitoring** reads `/var/log/auth.log` — contains usernames and source IPs
- **SQLite database** (`~/.bluekit/sentinel/sentinel.db`) contains sensitive operational data — protect it
- **Web dashboard** exposes findings — always use `--auth-token` + TLS for remote binds

## 🔐 Recommended Security Practices

If you deploy BlueKit Sentinel in production:

1. **Run with least privilege** — use `sudo` only when necessary
2. **Protect the data directory** — `~/.bluekit/` should be `0o700`
3. **Use TLS** for any remote web dashboard access
4. **Rotate auth tokens** periodically if using `--auth-token`
5. **Review suppression rules** — ensure they cannot hide real threats
6. **Monitor the audit log** — check `/suppressions` regularly
7. **Back up findings** before deleting the database
8. **Restrict access** to the web dashboard — do not expose to the internet

## 📜 Legal Notice

By using this software, you acknowledge that:

1. You are responsible for complying with all applicable laws
2. You have authorization to monitor the systems involved
3. You understand that this tool may capture sensitive data
4. The authors are not responsible for your actions
5. This tool is provided "AS IS" without warranty of any kind

See [LICENSE](LICENSE) for the full warranty disclaimer.

## 📞 Contact

**Graysentinel Cyber Defence Lab**

- 🌐 Website: [cyberdefencelab.co.in](https://cyberdefencelab.co.in)
- 📧 Email: [graysentinel.ai@gmail.com](mailto:graysentinel.ai@gmail.com)
- 💼 Founder: [linkedin.com/in/ritikshrivas312](https://linkedin.com/in/ritikshrivas312)

---

*Last updated: 2025*
