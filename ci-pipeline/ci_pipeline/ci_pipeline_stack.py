from aws_cdk import (
    core,
    aws_codebuild as codebuild,
    aws_codecommit as codecommit,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_lambda as lambda_,
    aws_s3 as s3,
)


class PipelineStack(core.Stack):
    def __init__(
        self,
        scope: core.Construct,
        id: str,
        *,
        lambda_code: lambda_.CfnParametersCode = None,
        **kwargs
    ) -> None:
        super().__init__(scope, id, **kwargs)

        code = codecommit.Repository.from_repository_name(
            self,
            "Mechanical Rock GitHub",
            "https://github.com/MechanicalRock/truffleHog",
        )

        codebuild_test_phase = codebuild.PipelineProject(
            self,
            "Run_Tests",
            build_spec=codebuild.BuildSpec.from_object(
                dict(
                    version="0.2",
                    phases=dict(
                        install=dict(commands="pip install -r requirements.txt"),
                        build=dict(commands=["behave", "pytest"]),
                    ),
                    environment=dict(
                        buildImage=codebuild.LinuxBuildImage.UBUNTU_14_04_NODEJS_10_14_1
                    ),
                )
            ),
        )

        source_output = codepipeline.Artifact()

        codepipeline.Pipeline(
            self,
            "MechanicalHog CI/CD Pipeline",
            stages=[
                codepipeline.StageProps(
                    stage_name="Source",
                    actions=[
                        codepipeline_actions.CodeCommitSourceAction(
                            action_name="CodeCommit_Source",
                            repository=code,
                            output=source_output,
                        )
                    ],
                ),
                codepipeline.StageProps(
                    stage_name="Run_Tests",
                    actions=[
                        codepipeline_actions.CodeBuildAction(
                            action_name="Run_Tests",
                            project=codebuild_test_phase,
                            input=source_output,
                        )
                    ],
                ),
            ],
        )
