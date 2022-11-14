import enum
import collections

from .parser import CommandParser
from woff.console.io import IO


class CommandMenu(object):
    def __init__(self):
        self.prompt = '>>> '
        self.parser = CommandParser()
        self._active = False

    def argument_handler(self, args):
        """
        Menangani argumen baris perintah.
        """
        pass

    def interrupt_handler(self):
        """
        Menangani interupsi keyboard di loop input.
        """
        self.stop()

    def start(self):
        """
        Memulai loop masukan menu.
        Perintah akan diproses dan ditangani.
        """
        self._active = True

        while self._active:
            try:
                command = IO.input(self.prompt)
            except KeyboardInterrupt:
                self.interrupt_handler()
                break

            # split command by spaces and parse the arguments
            parsed_args = self.parser.parse(command.split())
            if parsed_args is not None:
                self.argument_handler(parsed_args)

    def stop(self):
        """
        Memutus loop input menu
        """
        self._active = False
