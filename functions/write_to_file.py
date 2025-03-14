def write_to_file(data, filename) -> None: 
  file = open(filename, "w")
  file.write(data)
  file.close()
  return