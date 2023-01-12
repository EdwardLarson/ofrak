import sys

from ofrak.cli.command.deps import DepsCommand
from ofrak.cli.command.identify import IdentifyCommand
from ofrak.cli.command.list import ListCommand
from ofrak.cli.command.unpack import UnpackCommand
from ofrak.cli.ofrak_cli import OFRAKCommandLineInterface

if __name__ == "__main__":
    ofrak_cli = OFRAKCommandLineInterface(
        (ListCommand(), DepsCommand(), IdentifyCommand(), UnpackCommand())
    )
    ofrak_cli.parse_and_run(sys.argv[1:])
