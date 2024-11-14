class Packet:
  def __init__(self,src,dst,content):
    self._src = src
    self._dst = dst
    self._content = content 

  def get_content(self):
    return self._content


class Detection:
  def detect(self,packet):
    raise NoImplentedError("Subclass should be implemented this way.")

class SignatureDetection(Detection):
  def __init__(self,signatures):
    self.signatures = signestures

  def detect(self,packet):
    content = packet._get_content()
    for signature in self.signatures:
      if signature in content:
        return True 
  return False 

class AlertSystem:
  def alert(self,message):
    print(f"ALERT: {message}")

