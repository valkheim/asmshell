import os

from asmshell import commands, config, repl


def main() -> None:
    config.config.commands = {
        ((".h", ".help"), "This help", commands.help),
        ((".q", ".quit"), "Quit this program", commands.quit),
        ((".cls", ".clear"), "Clear screen", commands.clear),
        (
            (".r", ".reg", ".registers"),
            "Display registers",
            commands.registers,
        ),
        ((".s", ".stack"), "Display the stack", commands.stack),
    }
    commands.help()
    session = repl.Repl()
    session.enable_history(
        os.getenv("ASMSHELL_HISTORY_FILE", "~/.asms_history")
    )
    session.start()


if __name__ == "__main__":
    main()
