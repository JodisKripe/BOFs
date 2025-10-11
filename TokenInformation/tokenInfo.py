from havoc import Demon, RegisterCommand, RegisterModule

def getToken(demonID, *params):
    TaskID  : str = None
    demon   : Demon = None
    demon = Demon(demonID)

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f'Getting current token information\n' )

    demon.InlineExecute(TaskID, "go" , f"whoami.o", b'',False) # Change this as per situation. The location has to be in respext to the python script
    
    return TaskID

RegisterCommand( getToken, "", "getToken", "This runs a BOF which fetches token information using Win32 API", 0, "", "")