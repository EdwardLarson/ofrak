import logging
from argparse import ArgumentDefaultsHelpFormatter, Namespace

from ofrak.cli.ofrak_cli import OfrakCommandRunsScript
from ofrak.gui.server import open_gui
from ofrak.ofrak_context import OFRAKContext

LOGGER = logging.getLogger(__name__)


class GUICommand(OfrakCommandRunsScript):
    def create_parser(self, ofrak_subparsers):
        gui_parser = ofrak_subparsers.add_parser(
            "gui",
            help="Launch the OFRAK GUI server.",
            description="Launch the OFRAK GUI server.",
            formatter_class=ArgumentDefaultsHelpFormatter,
        )
        gui_parser.add_argument(
            "-H",
            "--hostname",
            action="store",
            help="Set GUI server host address.",
            default="127.0.0.1",
        )
        gui_parser.add_argument(
            "-p",
            "--port",
            action="store",
            type=int,
            help="Set GUI server host port.",
            default=8080,
        )
        gui_parser.add_argument(
            "--no-browser",
            action="store_true",
            help="Don't open the browser to the OFRAK GUI",
        )
        gui_parser.add_argument(
            "--file",
            "-f",
            required="False",
            action="append",
            help="Path to a file to load into OFRAK when starting the GUI (multiple may be "
            "provided)",
            default=[],
        )
        self.add_ofrak_arguments(gui_parser)
        return gui_parser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: Namespace):  # pragma: no cover
        if len(args.file):
            for path in args.file:
                _ = await ofrak_context.create_root_resource_from_file(path)
        server = await open_gui(
            args.hostname,
            args.port,
            open_in_browser=(not args.no_browser),
            ofrak_context=ofrak_context,
        )
        await server.run_until_cancelled()
