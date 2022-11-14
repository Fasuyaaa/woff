import enum
import collections

from woff.console.io import IO


class CommandParser(object):
    class CommandType(enum.Enum):
        PARAMETER_COMMAND = 1
        FLAG_COMMAND = 2
        PARAMETERIZED_FLAG_COMMAND = 3

    FlagCommand = collections.namedtuple('FlagCommand', 'type, identifier, name')
    ParameterCommand = collections.namedtuple('ParameterCommand', 'type name')
    Subparser = collections.namedtuple('Subparser', 'identifier subparser handler')

    def __init__(self):
        self._flag_commands = []
        self._parameter_commands = []
        self._subparsers = []

    def add_parameter(self, name):
        """
        Menambahkan perintah parameter yang tidak memerlukan pengenal.
        Hal ini diperlukan untuk mencakup semua perintah parameter.

        contoh: '24' atau 'halo'
        Keduanya adalah nilai mandiri (parameter).
        """
        command = CommandParser.ParameterCommand(
            type=CommandParser.CommandType.PARAMETER_COMMAND,
            name=name
        )

        self._parameter_commands.append(command)

    def add_flag(self, identifier, name):
        """
        Menambahkan perintah flag yang tidak membawa nilai apa pun.
        Flag adalah opsional.
        contoh: '-verbose'
        """
        command = CommandParser.FlagCommand(
            type=CommandParser.CommandType.FLAG_COMMAND,
            identifier=identifier,
            name=name
        )

        self._flag_commands.append(command)

    def add_parameterized_flag(self, identifier, name):
        """
        Menambahkan flag berparameter yang membawa nilai.
        Flag parameter adalah opsional.
        contoh: '-ip 192.168.0.0.1'
        """
        command = CommandParser.FlagCommand(
            type=CommandParser.CommandType.PARAMETERIZED_FLAG_COMMAND,
            identifier=identifier,
            name=name
        )

        self._flag_commands.append(command)

    def add_subparser(self, identifier, handler=None):
        """
        Membuat subparser dan menambahkan perintah ke parser ini, menjadikannya induknya.
        Subparser adalah parser mandiri yang dapat berisi perintah itu sendiri.

        contoh: 'git clone'
        Dalam hal ini 'git' adalah induk dan 'clone' subparser
        """
        subparser = CommandParser()
        command = CommandParser.Subparser(
            identifier=identifier,
            subparser=subparser,
            handler=handler
        )

        self._subparsers.append(command)
        return subparser

    def parse(self, command):
        """
        Mem-parsing daftar argumen yang diberikan
        """
        names = [x.name for x in (self._flag_commands + self._parameter_commands)]
        result_dict = dict.fromkeys(names, None)
        
        skip_next = False

        for i, arg in enumerate(command):
            if skip_next:
                skip_next = False
                continue

            if i == 0:
                
                for sp in self._subparsers:
                    if sp.identifier == arg:
                        
                        result = sp.subparser.parse(command[(i + 1):])
                        if result is not None and sp.handler is not None:
                            
                            sp.handler(result)

                        return result
            
            
            is_arg_processed = False

            for cmd in self._flag_commands:
                if cmd.identifier == arg:
                    if cmd.type == CommandParser.CommandType.FLAG_COMMAND:
                        
                        result_dict[cmd.name] = True
                        is_arg_processed = True
                        break
                    elif cmd.type == CommandParser.CommandType.PARAMETERIZED_FLAG_COMMAND:
                        if (len(command) - 1) < (i + 1):
                            
                            IO.error('parameter untuk flag {}{}{} hilang'.format(IO.Fore.LIGHTYELLOW_EX, cmd.name, IO.Style.RESET_ALL))
                            return

                        
                        value = command[i + 1]
                        result_dict[cmd.name] = value

                        
                        skip_next = True

                        is_arg_processed = True
                        break
            
            if not is_arg_processed:
                for cmd in self._parameter_commands:
                    
                    if result_dict[cmd.name] is None:
                        
                        result_dict[cmd.name] = arg
                        is_arg_processed = True
                        break

            if not is_arg_processed:
                IO.error('{}{}{} command tidak diketahui.'.format(IO.Fore.LIGHTYELLOW_EX, arg, IO.Style.RESET_ALL))
                return

       
        for cmd in self._parameter_commands:
            if result_dict[cmd.name] is None:
                IO.error('parameter {}{}{} hilang'.format(IO.Fore.LIGHTYELLOW_EX, cmd.name, IO.Style.RESET_ALL))
                return

        for cmd in self._flag_commands:
            if cmd.type == CommandParser.CommandType.FLAG_COMMAND:
                if result_dict[cmd.name] is None:
                    result_dict[cmd.name] = False

        result_tuple = collections.namedtuple('ParseResult', sorted(result_dict))
        return result_tuple(**result_dict)