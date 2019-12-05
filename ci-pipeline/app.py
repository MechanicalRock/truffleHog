#!/usr/bin/env python3

from aws_cdk import core

from ci_pipeline.ci_pipeline_stack import PipelineStack


app = core.App()
PipelineStack(app, "ci-pipeline", env={"region": "ap-southeast-2"})

app.synth()
