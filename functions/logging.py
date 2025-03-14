from datetime import datetime

# msg = what is the error  Module = module name(nmap) Cataegory = 0 to 3 depending what log type options = {"debug":True} (like varibel we want to show)
def log(msg: str, module:str, category:int=0, options:dict=None) -> None:
  category_name = ""
  if category == 3 and options["debug"] != True: return
  match category:
    case 0: category_name = "LOG"
    case 1: category_name = "WARN"
    case 2: category_name = "ERROR"
    case 3: category_name = "DEBUG"
  print(f'[{datetime.now()}]\t{category_name}\t-\t{module}\t|\t{msg}')