# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
data "aws_iam_policy_document" "read" {
  /* block
     comment */
  statement {
    sid    = "ReadOwnPrefix"
    effect = "Allow" // trailing
    actions = [
      "s3:GetObject", # first
      "s3:ListBucket",
    ]
    resources = ["arn:aws:s3:::${var.bucket}/${lookup(local.m, "k", "}")}/*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.app.arn]
    }
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["home/$${aws:username}/*", "${var.env}-%{ if var.x }a%{ endif }"]
    }
  }
  dynamic "statement" {
    for_each = var.extra
    content {
      actions   = statement.value.actions
      resources = ["*"]
      dynamic "condition" {
        for_each = statement.value.conditions
        content {
          test     = condition.value.test
          variable = "aws:SourceAccount"
          values   = [condition.value.account]
        }
      }
    }
  }
}

data "aws_iam_policy_document" "other" {
  statement {
    not_actions   = ["iam:*"]
    not_resources = ["arn:aws:iam::*:role/x"]
  }
}
