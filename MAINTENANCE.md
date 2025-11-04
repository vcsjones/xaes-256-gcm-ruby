# Release Process

1. Update `version.rb` to contain the new desired version.
2. Create a tag. It must be prefixed with `v` followed by the version, such as `v1.0` or `v5.2.1`. For example, `git tag -a -s v1.1`.
    * Do _not_ create a new release in GitHub. The release with attestation artifacts will automatically be created.
    * Tags should be annotated and signed.
3. Push the tag.
5. The publish workflow will automatically create a gem, an attestation, and a GitHub release for the new tag.
6. The new release will be published as a draft. Modify the draft release with appropriate release notes and publish it.
