def setUnstableOnShellResult =
{
  resultShell, resultUnstable ->
  if(resultShell == resultUnstable)
  {
    currentBuild.result = 'UNSTABLE'
  }
}

def doStage =
{
  stageName, stageBody ->
  stage (stageName)
  {
    gitlabCommitStatus(name: stageName)
    {
      stageBody()
    }

    if (currentBuild.result == 'UNSTABLE')
    {
      updateGitlabCommitStatus(name: stageName, state: 'failed')
    }
  }
}

def stageCheckout =
{
  gitlabUrl           = 'http://gitlab.dmz/leighgarbs/'
  gitlabUrlNetsuspend = gitlabUrl + 'netsuspend.git'
  gitlabUrlBin        = gitlabUrl + 'bin.git'

  deleteDir()

  checkout changelog: true, poll: true, scm: [$class: 'GitSCM',
    branches: [[name: env.BRANCH_NAME]],
    browser: [$class: 'GitLab',
             repoUrl: gitlabUrlNetsuspend,
             version: '11.0'],
    extensions: [[$class: 'SubmoduleOption',
                disableSubmodules: false,
                parentCredentials: false,
                recursiveSubmodules: true,
                reference: '',
                trackingSubmodules: false]],
    submoduleCfg: [],
    userRemoteConfigs: [[credentialsId: '',
                       url: gitlabUrlNetsuspend]]]

  sh """
    git clone $gitlabUrlBin $TEMP_BIN
  """
}

def stageCppcheck =
{
  def shellReturnStatus = sh returnStatus: true, script: '''
    $TEMP_BIN/run-cppcheck -J --suppress=unusedFunction .
  '''

  setUnstableOnShellResult(shellReturnStatus, 1)

  publishCppcheck displayAllErrors: false,
                  displayErrorSeverity: true,
                  displayNoCategorySeverity: true,
                  displayPerformanceSeverity: true,
                  displayPortabilitySeverity: true,
                  displayStyleSeverity: true,
                  displayWarningSeverity: true,
                  pattern: 'cppcheck-result.xml',
                  severityNoCategory: false
}

def stageBuildRelease =
{
  sh '''
    $TEMP_BIN/run-cmake --release .
    make
  '''
}

def stageDetectWarnings =
{
  warnings canComputeNew: false,
           canResolveRelativePaths: false,
           categoriesPattern: '',
           consoleParsers: [[parserName: 'GNU Make + GNU C Compiler (gcc)']]
}

def stageBuildDebug =
{
  sh '''
    $TEMP_BIN/run-cmake --debug .
    make
  '''
}

def stageClangStaticAnalysis =
{
  sh '''
    rm CMakeCache.txt
    rm -rf CMakeFiles
    scan-build $TEMP_BIN/run-cmake --debug .
    scan-build -o clangScanBuildReports -v -v --use-cc clang \
      --use-analyzer=/usr/bin/clang make
  '''
}

stages = [[name: 'Checkout',              body: stageCheckout],
          [name: 'cppcheck',              body: stageCppcheck],
          [name: 'Release Build',         body: stageBuildRelease],
          [name: 'Detect Warnings',       body: stageDetectWarnings],
          [name: 'Debug Build',           body: stageBuildDebug],
          [name: 'Clang Static Analyzer', body: stageClangStaticAnalysis]]

stageNames = []
for (i = 0; i < stages.size(); i++)
{
  stageNames.plus(stages[i].name)
}

properties([[$class: 'GitLabConnectionProperty',
            gitLabConnection: 'gitlab.dmz'],
            pipelineTriggers([[$class: 'GitLabPushTrigger',
                              triggerOnPush: true,
                              triggerOnMergeRequest: true,
                              skipWorkInProgressMergeRequest: true,
                              pendingBuildName: stageNames[0]]])])

gitlabBuilds(builds: stageNames)
{
  node ()
  {
    for (i = 0; i < stages.size(); i++)
    {
      doStage(stages[i].name, stages[i].body)
    }
  }
}
