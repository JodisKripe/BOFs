from havoc import Demon, RegisterCommand, RegisterModule

def whomi(demonID, *params):
    TaskID  : str = None
    demon   : Demon = None
    demon = Demon(demonID)

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f'Running the custom whoami')

    demon.InlineExecute(TaskID, "go" , f"whoami.o", b'',False) # Change this as per situation. The location has to be in respect to the python script
    
    return TaskID

RegisterCommand( whomi, "", "whomi", "This runs a BOF which fetches the Computername and Username using Win32 API", 0, "", "")