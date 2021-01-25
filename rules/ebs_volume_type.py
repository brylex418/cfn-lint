from cfnlint import CloudFormationLintRule
from cfnlint import RuleMatch


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


#### EXAMPLE RULE ####


# from cfnlint import CloudFormationLintRule
# from cfnlint import RuleMatch


# class S3BucketsNotPublic(CloudFormationLintRule):
#   """Check if S3 Bucket is Not Public"""
#   id = 'E9020'
#   shortdesc = 'S3 Buckets must never be public'
  
#   def match(self, cfn):
#     matches = list()
#     recordsets = cfn.get_resources(['AWS::S3::Bucket'])
#     for name, recordset in recordsets.items():
#       path = ['Resources', name, 'Properties']
#       full_path = ('/'.join(str(x) for x in path))
#       if isinstance(recordset, dict):
#         props = recordset.get('Properties')
#         if props:
#           access_control = props.get('AccessControl')
#           if access_control:
#             forbidden_values = ['PublicRead','PublicReadWrite']
#           if access_control in forbidden_values:
#             message =  "Property AccessControl set to {0} is forbidden in {1}"
#             matches.append(RuleMatch(
#               path,
#               message.format(access_control, full_path)
#             ))
#     return matches