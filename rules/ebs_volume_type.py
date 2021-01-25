from cfnlint.rules import CloudFormationLintRule
from cfnlint.rules import RuleMatch


class EBSVolumeType(CloudFormationLintRule):
  """Check if EBS Volumes are using GP2 Volume Type"""
  id = 'E9020'
  shortdesc = 'Outposts only support GP2 volume types'

  def match(self, cfn):
    matches = list()
    recordsets = cfn.get_resources(['AWS::EC2::Volume'])
    for name, recordset in recordsets.items():
      path = ['Resources', name, 'Properties']
      full_path = ('/'.join(str(x) for x in path))
      if isinstance(recordset, dict):
        props = recordset.get('Properties')
        if props:
          volume_type = props.get('VolumeType')
          if volume_type:
            forbidden_values = ['GP3','io1','io2','hdd']
          if volume_type in forbidden_values:
            message =  "Property VolumeType set to {0} is not supported on Outposts in {1}"
            matches.append(RuleMatch(
              path,
              message.format(volume_type, full_path)
            ))
    return matches
  
class EBSEncrypted(CloudFormationLintRule):
  """Check if EBS Volumes are using GP2 Volume Type"""
  id = 'E9021'
  shortdesc = 'Outposts only support encrypted volumes'

  def match(self, cfn):
    matches = list()
    recordsets = cfn.get_resources(['AWS::EC2::Volume'])
    for name, recordset in recordsets.items():
      path = ['Resources', name, 'Properties']
      full_path = ('/'.join(str(x) for x in path))
      if isinstance(recordset, dict):
        props = recordset.get('Properties')
        if props:
          encryption = props.get('Encrypted')
          if encryption:
            values = ['false', 'FALSE']
          if encryption in values:
            message =  "Property VolumeType set to {0} is not supported on Outposts in {1}"
            matches.append(RuleMatch(
              path,
              message.format(encryption, full_path)
            ))
    return matches
