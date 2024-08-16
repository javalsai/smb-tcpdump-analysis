# smb-tcpdump-analysis
This is just a rust tool that tries to analyze `tcpdump` output as SMB traffic and print the "conversation" in simple terms.

This doesn't have to be SMB exclusive, it has a module dedicated to parse tcpdump output, so if you just wanna use that is fine, the license allows anything.

Perfect (IMO) for when just windows doesn't load the SMB share and the most useful thing you have is a generic error code and "Unspecified Error".

> [!WARNING]
> This is WIP, inconsistent, still not documented and potential breaking changes to come.

> [!NOTE]
> I'll attach a screenshot of the output when I like how this is going, as I said, **WIP**.

# Contributing
Sure, I'll possibly keep an eye on this, and if you manage to add support to this or just fix something, consider opening a PR to help others using this tool.

# Features
Yeah, there's a feature called color but I have a bunch of colors hardcoded without checking for it (I think just in `main.rs` tho), so disabling it still leaves colors around.
