# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.12.1 (2022-03-29)

### New Features

 - <csr-id-5b412d04ebc9a0bb0149a7dbf5ebf3c6116261c3/> allow custom hash parameters to be specified

### Bug Fixes

 - <csr-id-053e64ea1eea16c582df8b506d024326e075b876/> fix invalid env syntax
 - <csr-id-a3ceaa9a72debf7428cce2618fe6828ad66ff0b9/> code coverage only works on nightly
 - <csr-id-1b74d944218587dd0fa60bc75db2eca1d5d7057d/> ensure ExecutionStack cannot exceed MAX_STACK_SIZE

### Performance

 - <csr-id-5d069a362ea70fe81fdb4955801ce4b701705ca1/> lazily compress RistrettoPublicKey
   Implement lazy compression for RistrettoPublicKey using thread-safe [`OnceCell`](https://docs.rs/once_cell/latest/once_cell/index.html) (currently unstable in std) 
   
   ![image](https://user-images.githubusercontent.com/1057902/148182436-1a29d610-4727-49be-9339-f83b53b568ae.png)
   
   Red is on current main branch, blue are the changes in the PR
   
   - Minor optimisation for lexicographical public key ordering: using reference to the underlying compressed array rather than copying the array onto the stack and then creating a reference

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 3 commits contributed to the release.
 - 1 day passed between releases.
 - 3 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 2 unique issues were worked on: [#81](https://github.comgit//sdbondi/tari-crypto/issues/81), [#86](https://github.comgit//sdbondi/tari-crypto/issues/86)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#81](https://github.comgit//sdbondi/tari-crypto/issues/81)**
    - remove tari script ([`5fd06b7`](https://github.comgit//sdbondi/tari-crypto/commit/5fd06b7fe407ce720759d377265905cf719371dd))
 * **[#86](https://github.comgit//sdbondi/tari-crypto/issues/86)**
    - add wasm build artifacts and test run ([`e796bea`](https://github.comgit//sdbondi/tari-crypto/commit/e796bea54ab8c27f1f47ccc36a3401d63f64f1f5))
 * **Uncategorized**
    - use standard-version ([`53a0dbd`](https://github.comgit//sdbondi/tari-crypto/commit/53a0dbdfa701f6037b59f671b8238bf1390ba69f))
</details>

## v0.12.0 (2022-01-18)

### New Features

 - <csr-id-a5defb77e4e212ca5f3fe5e8a1bfe57810efd83e/> add pull request title check
   This PR adds a lint check for pull request titles to ensure they conform to the conventional commits specification
 - <csr-id-f608ccfe96c249c63ba91d077145325a47d0aa4d/> add CheckMultiSig and CheckMultiSigVerify


### chore (BREAKING)

 - <csr-id-09cc52787272ced3a1a8c9f2edc1e0221f9d8faa/> update rust toolchain (proc_macro_is_available feature)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 9 commits contributed to the release over the course of 119 calendar days.
 - 134 days passed between releases.
 - 5 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 7 unique issues were worked on: [#58](https://github.comgit//sdbondi/tari-crypto/issues/58), [#59](https://github.comgit//sdbondi/tari-crypto/issues/59), [#60](https://github.comgit//sdbondi/tari-crypto/issues/60), [#61](https://github.comgit//sdbondi/tari-crypto/issues/61), [#62](https://github.comgit//sdbondi/tari-crypto/issues/62), [#68](https://github.comgit//sdbondi/tari-crypto/issues/68), [#74](https://github.comgit//sdbondi/tari-crypto/issues/74)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#58](https://github.comgit//sdbondi/tari-crypto/issues/58)**
    - run clippy and cov on every pr ([`e18de46`](https://github.comgit//sdbondi/tari-crypto/commit/e18de46e99734a32eb012135ab846a0c721582b9))
 * **[#59](https://github.comgit//sdbondi/tari-crypto/issues/59)**
    - add CheckMultiSig and CheckMultiSigVerify ([`f608ccf`](https://github.comgit//sdbondi/tari-crypto/commit/f608ccfe96c249c63ba91d077145325a47d0aa4d))
 * **[#60](https://github.comgit//sdbondi/tari-crypto/issues/60)**
    - Reduce memory overhead ([`99e8d18`](https://github.comgit//sdbondi/tari-crypto/commit/99e8d1882be3d8f5bc96b572db9259d6eae640dd))
 * **[#61](https://github.comgit//sdbondi/tari-crypto/issues/61)**
    - Don't do call coverage on PRs ([`75a6456`](https://github.comgit//sdbondi/tari-crypto/commit/75a6456a48d1f6dc36e58f49a215a3e9f0c465ab))
 * **[#62](https://github.comgit//sdbondi/tari-crypto/issues/62)**
    - add pull request title check ([`a5defb7`](https://github.comgit//sdbondi/tari-crypto/commit/a5defb77e4e212ca5f3fe5e8a1bfe57810efd83e))
 * **[#68](https://github.comgit//sdbondi/tari-crypto/issues/68)**
    - remove from circle ci ([`21583f3`](https://github.comgit//sdbondi/tari-crypto/commit/21583f3330b99bf13f514ec3459f9b2c47d5d56e))
 * **[#74](https://github.comgit//sdbondi/tari-crypto/issues/74)**
    - update rust toolchain (proc_macro_is_available feature) ([`09cc527`](https://github.comgit//sdbondi/tari-crypto/commit/09cc52787272ced3a1a8c9f2edc1e0221f9d8faa))
 * **Uncategorized**
    - fix conflict ([`19193bf`](https://github.comgit//sdbondi/tari-crypto/commit/19193bf341c4f246a083f06d57b8f16e7d5c7172))
    - fix all clippy warnings ([`3a002ee`](https://github.comgit//sdbondi/tari-crypto/commit/3a002eeb5b349a479a89e4de37308e3dd084cce3))
</details>

## v0.11.1 (2021-09-06)

### Bug Fixes

 - <csr-id-8864b5a20bd55c8e075be67b132daebe22762e0c/> remove extra compress call during pubkey::deserialize
 - <csr-id-3862d2845e045d0d2e46590107b3438eb4cdeb20/> remove extra compress call during pubkey::deserialize

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 21 commits contributed to the release.
 - 63 days passed between releases.
 - 6 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 7 unique issues were worked on: [#50](https://github.comgit//sdbondi/tari-crypto/issues/50), [#51](https://github.comgit//sdbondi/tari-crypto/issues/51), [#52](https://github.comgit//sdbondi/tari-crypto/issues/52), [#53](https://github.comgit//sdbondi/tari-crypto/issues/53), [#54](https://github.comgit//sdbondi/tari-crypto/issues/54), [#55](https://github.comgit//sdbondi/tari-crypto/issues/55), [#56](https://github.comgit//sdbondi/tari-crypto/issues/56)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#50](https://github.comgit//sdbondi/tari-crypto/issues/50)**
    - Increase coverage ([`67e429e`](https://github.comgit//sdbondi/tari-crypto/commit/67e429eddca1261148d7c5ba9c52fe17be63f918))
 * **[#51](https://github.comgit//sdbondi/tari-crypto/issues/51)**
    - Minor clippy fixes ([`262590d`](https://github.comgit//sdbondi/tari-crypto/commit/262590dd856f3f1fc44c8bff7ec705e2ae526f97))
 * **[#52](https://github.comgit//sdbondi/tari-crypto/issues/52)**
    - remove leaky mock and remove libc dependency ([`34912d1`](https://github.comgit//sdbondi/tari-crypto/commit/34912d148c6f15813522972a6ecbe03daf7eef04))
 * **[#53](https://github.comgit//sdbondi/tari-crypto/issues/53)**
    - WASM unit tests ([`48b68d2`](https://github.comgit//sdbondi/tari-crypto/commit/48b68d2d3d05412952ae1dc054c6ddafc0f82c20))
 * **[#54](https://github.comgit//sdbondi/tari-crypto/issues/54)**
    - Minor optimisation to SchnorrSignature ord impl ([`f9fb20e`](https://github.comgit//sdbondi/tari-crypto/commit/f9fb20eabc5529f68cffa436b7f12a485629ceb9))
 * **[#55](https://github.comgit//sdbondi/tari-crypto/issues/55)**
    - revert naming in wasm functions ([`93927b2`](https://github.comgit//sdbondi/tari-crypto/commit/93927b2fd9e608f354286c29e2ba243ae666fc92))
 * **[#56](https://github.comgit//sdbondi/tari-crypto/issues/56)**
    - remove extra compress call during pubkey::deserialize ([`8864b5a`](https://github.comgit//sdbondi/tari-crypto/commit/8864b5a20bd55c8e075be67b132daebe22762e0c))
 * **Uncategorized**
    - v0.11.1 ([`459249f`](https://github.comgit//sdbondi/tari-crypto/commit/459249f9211711ae2e2659f622ad46645fe7fae5))
    - run clippy and cov on every pr ([`8721e10`](https://github.comgit//sdbondi/tari-crypto/commit/8721e10de05bc98d419ab385865a221e10411279))
    - add clippy and rustfmt to PRs ([`e1b1a1b`](https://github.comgit//sdbondi/tari-crypto/commit/e1b1a1bc6fe5f136ea407bc243ca999cb2cc577c))
    - review comments 2: electric boogaloo ([`31a1e5d`](https://github.comgit//sdbondi/tari-crypto/commit/31a1e5d4a4456bee9e1d9ee04f32b2ff51eabd5c))
    - Revert naming in wasm functions ([`a21241e`](https://github.comgit//sdbondi/tari-crypto/commit/a21241e6a20215ca7d39193f0e9e47588302d5c3))
    - check that sigs are only counted once in checkmultisig ([`27ef670`](https://github.comgit//sdbondi/tari-crypto/commit/27ef6702a70d7ab7adb32c714d01bfe685bb742f))
    - Remove leaky mock and remove libc dependency ([`0d17b46`](https://github.comgit//sdbondi/tari-crypto/commit/0d17b461c735fbab4e7b3b90a0f51ce64917598a))
    - review comments ([`1c4dde2`](https://github.comgit//sdbondi/tari-crypto/commit/1c4dde280e177f3a8c071411be08a40b10fc0a2c))
    - remove extra compress call during pubkey::deserialize ([`3862d28`](https://github.comgit//sdbondi/tari-crypto/commit/3862d2845e045d0d2e46590107b3438eb4cdeb20))
    - DRY up multisig args ([`b4d4075`](https://github.comgit//sdbondi/tari-crypto/commit/b4d4075a0a5aae623e79833fac74dac28601cae0))
    - Bump patch version ([`1a18684`](https://github.comgit//sdbondi/tari-crypto/commit/1a1868466512550c0e479542fdd520afda433d02))
    - update script! macro to allow opcodes with multiple args ([`191bd48`](https://github.comgit//sdbondi/tari-crypto/commit/191bd48849849a9212d73146bf0c0c61fe612a85))
    - Update README changelog ([`f55bb7a`](https://github.comgit//sdbondi/tari-crypto/commit/f55bb7a50eff0933d5184f0a44671c7d7ae2e69d))
    - bump circleci docker ([`e85ad2b`](https://github.comgit//sdbondi/tari-crypto/commit/e85ad2b90bfeff4a6e7c46339a0db8291298d6aa))
</details>

## v0.11.0 (2021-07-05)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 6 commits contributed to the release.
 - 2 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 2 unique issues were worked on: [#48](https://github.comgit//sdbondi/tari-crypto/issues/48), [#49](https://github.comgit//sdbondi/tari-crypto/issues/49)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#48](https://github.comgit//sdbondi/tari-crypto/issues/48)**
    - Source coverage ([`fa20692`](https://github.comgit//sdbondi/tari-crypto/commit/fa2069294374c828b733afbfea17c687b6e83906))
 * **[#49](https://github.comgit//sdbondi/tari-crypto/issues/49)**
    - Migrate to digest 0.9 ([`f9428bc`](https://github.comgit//sdbondi/tari-crypto/commit/f9428bc8156c9f919ef011fb3d158ec871d35640))
 * **Uncategorized**
    - Fix source_cov GA script ([`7cf7fe1`](https://github.comgit//sdbondi/tari-crypto/commit/7cf7fe1553962b43b15332dcddafb9c99891153f))
    - add max sig limit ([`95b499b`](https://github.comgit//sdbondi/tari-crypto/commit/95b499b631a61818a075ec7c97053849186c65b6))
    - change CheckMultiSig data to script instead of stack ([`f9c456a`](https://github.comgit//sdbondi/tari-crypto/commit/f9c456ac965710740dc65cab4bb26cec13a4befd))
    - add failing test for same signer ([`0ef761b`](https://github.comgit//sdbondi/tari-crypto/commit/0ef761b21ad0ce06e7fe5bbb1950e134011bedee))
</details>

## v0.10.0 (2021-07-02)

### New Features

 - <csr-id-9e5627123a45bfebabdb56777c9be4d83b92b07b/> add CheckMultiSig/Verify implementation and tests

### Bug Fixes

 - <csr-id-d5d9bc738364a35c458c5dfe45e562ee4102c105/> edge case bugfix for conditionals

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 17 commits contributed to the release over the course of 99 calendar days.
 - 106 days passed between releases.
 - 6 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 7 unique issues were worked on: [#38](https://github.comgit//sdbondi/tari-crypto/issues/38), [#41](https://github.comgit//sdbondi/tari-crypto/issues/41), [#43](https://github.comgit//sdbondi/tari-crypto/issues/43), [#44](https://github.comgit//sdbondi/tari-crypto/issues/44), [#45](https://github.comgit//sdbondi/tari-crypto/issues/45), [#46](https://github.comgit//sdbondi/tari-crypto/issues/46), [#47](https://github.comgit//sdbondi/tari-crypto/issues/47)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#38](https://github.comgit//sdbondi/tari-crypto/issues/38)**
    - Add serde to the ExecutionStack ([`f30d566`](https://github.comgit//sdbondi/tari-crypto/commit/f30d56670aff2b07c93d88859da40fffe51b01f3))
 * **[#41](https://github.comgit//sdbondi/tari-crypto/issues/41)**
    - Add private key utility functions to the WASM interface Merge pull request #41 ([`1620db4`](https://github.comgit//sdbondi/tari-crypto/commit/1620db4dd428dfb67179e8c6dd3bb1a6d04b67a9))
 * **[#43](https://github.comgit//sdbondi/tari-crypto/issues/43)**
    - Add commitment signature ([`45fba21`](https://github.comgit//sdbondi/tari-crypto/commit/45fba2160694ac19f51d6233fd5465da8a1614ee))
 * **[#44](https://github.comgit//sdbondi/tari-crypto/issues/44)**
    - Rust test coverage for ffi. ([`e1adaa2`](https://github.comgit//sdbondi/tari-crypto/commit/e1adaa2021641c02179645b8da700ba5c50836ad))
 * **[#45](https://github.comgit//sdbondi/tari-crypto/issues/45)**
    - Remove extra heap allocation in Blake256 ([`ea8998d`](https://github.comgit//sdbondi/tari-crypto/commit/ea8998d49b487be2cc6f1f1ae0078831a5e66dc6))
 * **[#46](https://github.comgit//sdbondi/tari-crypto/issues/46)**
    - Add `to_vec` function to comm sig ([`8fcba39`](https://github.comgit//sdbondi/tari-crypto/commit/8fcba398b4c36eb6bc2b931b6664e7233472c97e))
 * **[#47](https://github.comgit//sdbondi/tari-crypto/issues/47)**
    - Stable rust ([`dd05268`](https://github.comgit//sdbondi/tari-crypto/commit/dd052680aa7dc3fc2753a44d44e3bf5be282ba51))
 * **Uncategorized**
    - add github actions and update deps ([`ba29021`](https://github.comgit//sdbondi/tari-crypto/commit/ba29021b2b3c647a4e97ca7a0ef84272e6dde543))
    - update to nightly-2021-06-01 ([`5757d52`](https://github.comgit//sdbondi/tari-crypto/commit/5757d52fae4069e5f3a4deb34afc15f29c275c02))
    - test a newer version of the docker image nightly ([`cce1c93`](https://github.comgit//sdbondi/tari-crypto/commit/cce1c9315279d68fb28544d060cca7ea50cddf90))
    - add CheckMultiSig/Verify implementation and tests ([`9e56271`](https://github.comgit//sdbondi/tari-crypto/commit/9e5627123a45bfebabdb56777c9be4d83b92b07b))
    - v0.9.1 ([`ecd77ec`](https://github.comgit//sdbondi/tari-crypto/commit/ecd77ec2b8484d3e146257654dba28f854ca4410))
    - add test of 1 of 2 multisig using tariscript ([`3e76495`](https://github.comgit//sdbondi/tari-crypto/commit/3e76495a64df0e33df77fca5ad6b8f86afb1d0b6))
    - edge case bugfix for conditionals ([`d5d9bc7`](https://github.comgit//sdbondi/tari-crypto/commit/d5d9bc738364a35c458c5dfe45e562ee4102c105))
    - Add commitment signature ([`286cc30`](https://github.comgit//sdbondi/tari-crypto/commit/286cc30a1e91b25e4349212dd2ab72cc7ae555ce))
    - add reproducing case for if-then-else bug ([`8f9faeb`](https://github.comgit//sdbondi/tari-crypto/commit/8f9faebadd03e887fa83d8899150290b388486f5))
    - Add private key utility functions to the WASM interface ([`6b4ba72`](https://github.comgit//sdbondi/tari-crypto/commit/6b4ba726f9558c0b78defb6d7ba40fddad48d071))
</details>

## v0.9.0 (2021-03-18)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 7 commits contributed to the release over the course of 86 calendar days.
 - 86 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 6 unique issues were worked on: [#28](https://github.comgit//sdbondi/tari-crypto/issues/28), [#30](https://github.comgit//sdbondi/tari-crypto/issues/30), [#31](https://github.comgit//sdbondi/tari-crypto/issues/31), [#33](https://github.comgit//sdbondi/tari-crypto/issues/33), [#36](https://github.comgit//sdbondi/tari-crypto/issues/36), [#37](https://github.comgit//sdbondi/tari-crypto/issues/37)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#28](https://github.comgit//sdbondi/tari-crypto/issues/28)**
    - pubkey_from_hex function ([`ae9a3bf`](https://github.comgit//sdbondi/tari-crypto/commit/ae9a3bf6693fd8bc8f5042fc2be06b98f661b64e))
 * **[#30](https://github.comgit//sdbondi/tari-crypto/issues/30)**
    - Add tests to improve test coverage ([`b9d434b`](https://github.comgit//sdbondi/tari-crypto/commit/b9d434b19c48993d47da3a37b22548d6a3bab265))
 * **[#31](https://github.comgit//sdbondi/tari-crypto/issues/31)**
    - Fix grcov action ([`bd4fdb9`](https://github.comgit//sdbondi/tari-crypto/commit/bd4fdb9bff1134861d749f69d5fe04895d1cd37b))
 * **[#33](https://github.comgit//sdbondi/tari-crypto/issues/33)**
    - Expose fine-grained control of cc feature flags ([`c652175`](https://github.comgit//sdbondi/tari-crypto/commit/c6521759db51a0419b44ce81257f72469c6d8628))
 * **[#36](https://github.comgit//sdbondi/tari-crypto/issues/36)**
    - Update and implement opcodes from RFC 0202 with tests ([`9c62b97`](https://github.comgit//sdbondi/tari-crypto/commit/9c62b979f16ff1e0946d0c9f150cc1ce4938aaed))
 * **[#37](https://github.comgit//sdbondi/tari-crypto/issues/37)**
    - Add time locked contract example for TariScript ([`1648d00`](https://github.comgit//sdbondi/tari-crypto/commit/1648d000fef23618efb0c3338c61a871e5a996b9))
 * **Uncategorized**
    - Bump minor version ([`685d6fc`](https://github.comgit//sdbondi/tari-crypto/commit/685d6fc7fd4134932881b901ce12bb3cd20496aa))
</details>

## v0.8.2 (2020-12-21)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 3 commits contributed to the release over the course of 4 calendar days.
 - 19 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 2 unique issues were worked on: [#27](https://github.comgit//sdbondi/tari-crypto/issues/27), [#29](https://github.comgit//sdbondi/tari-crypto/issues/29)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#27](https://github.comgit//sdbondi/tari-crypto/issues/27)**
    - Align dalek version numbers ([`1be2029`](https://github.comgit//sdbondi/tari-crypto/commit/1be2029fbea60a8d50f77899276eda7622cb5d35))
 * **[#29](https://github.comgit//sdbondi/tari-crypto/issues/29)**
    - Bump cbindgen dep to fix security audit on Tari repo ([`1c1846e`](https://github.comgit//sdbondi/tari-crypto/commit/1c1846eb967ca4d7dcd92877b51133ba30a798a2))
 * **Uncategorized**
    - Bump patch version ([`45bfb4c`](https://github.comgit//sdbondi/tari-crypto/commit/45bfb4ce8fdcd6270053ee30b7843de3e7b74aa9))
</details>

## v0.8.0 (2020-12-01)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 19 commits contributed to the release over the course of 90 calendar days.
 - 106 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 7 unique issues were worked on: [#12](https://github.comgit//sdbondi/tari-crypto/issues/12), [#20](https://github.comgit//sdbondi/tari-crypto/issues/20), [#21](https://github.comgit//sdbondi/tari-crypto/issues/21), [#22](https://github.comgit//sdbondi/tari-crypto/issues/22), [#23](https://github.comgit//sdbondi/tari-crypto/issues/23), [#25](https://github.comgit//sdbondi/tari-crypto/issues/25), [#26](https://github.comgit//sdbondi/tari-crypto/issues/26)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#12](https://github.comgit//sdbondi/tari-crypto/issues/12)**
    - Tari Script ([`8dab24e`](https://github.comgit//sdbondi/tari-crypto/commit/8dab24e6448365172098f90c57cfd5a8361ef7a6))
 * **[#20](https://github.comgit//sdbondi/tari-crypto/issues/20)**
    - v0.8-RC ([`a212432`](https://github.comgit//sdbondi/tari-crypto/commit/a2124322878da12ff778a6101c0b24b92f1701df))
 * **[#21](https://github.comgit//sdbondi/tari-crypto/issues/21)**
    - Use the rust toolchain specified ([`7ee2dfb`](https://github.comgit//sdbondi/tari-crypto/commit/7ee2dfb24595e8a858ddd3f2f8de15793fa466a2))
 * **[#22](https://github.comgit//sdbondi/tari-crypto/issues/22)**
    - Basic FFI library ([`63fc9b4`](https://github.comgit//sdbondi/tari-crypto/commit/63fc9b49641838eaa9c2d42614c850db85af3e7d))
 * **[#23](https://github.comgit//sdbondi/tari-crypto/issues/23)**
    - Fix wasm_build for new version ([`e6085be`](https://github.comgit//sdbondi/tari-crypto/commit/e6085beb58c39d9cab213a1f1c00b77f35cfddbd))
 * **[#25](https://github.comgit//sdbondi/tari-crypto/issues/25)**
    - Integrate bulletproof rewinding ([`d09e1ec`](https://github.comgit//sdbondi/tari-crypto/commit/d09e1ec5c3368eb360126610fce88b857e07acff))
 * **[#26](https://github.comgit//sdbondi/tari-crypto/issues/26)**
    - Run cargo fmt --all ([`b9ffb9b`](https://github.comgit//sdbondi/tari-crypto/commit/b9ffb9bc64f837b66a008ef656a9d7ec5de7035f))
 * **Uncategorized**
    - Merge #24: Add signing methods for pre-determined nonces ([`981ba66`](https://github.comgit//sdbondi/tari-crypto/commit/981ba6653d1b78551c639054ad9f33deedb2b910))
    - Add signing methods for pre-determined nonces ([`6ed84e2`](https://github.comgit//sdbondi/tari-crypto/commit/6ed84e2b2c67031485e33ec7c92a89b3199f1157))
    - Merge #13: Add execution context ([`db112f6`](https://github.comgit//sdbondi/tari-crypto/commit/db112f6058d8c0b3c635f457e1afea134a7367da))
    - Fix conflicts ([`8259d14`](https://github.comgit//sdbondi/tari-crypto/commit/8259d142e595c1da18b7bf69cf38e97e5c690031))
    - Merge #17: Add sha3 as a hash function for tari_crypto ([`19fd735`](https://github.comgit//sdbondi/tari-crypto/commit/19fd73547ad36263e847b77c3f2e00bc23d0ddc1))
    - Add execution context ([`3bc468b`](https://github.comgit//sdbondi/tari-crypto/commit/3bc468bb342d76ee73b1aaf777b98305ab5ad0d9))
    - Add sha3 as a hash function for tari_crypto ([`1105b9c`](https://github.comgit//sdbondi/tari-crypto/commit/1105b9cd4d824b74716efdd3bd6d4a14c786f488))
    - Merge #18: Add blake3 ([`1fff94f`](https://github.comgit//sdbondi/tari-crypto/commit/1fff94f0f3cc1b15275f2ae35e46779a3924c6e5))
    - Merge #19: Add a function to the range proof trait ([`28e377e`](https://github.comgit//sdbondi/tari-crypto/commit/28e377ea6d4b0a7c5963b0481f6a9d1568151d50))
    - Add blake3 ([`ea6713b`](https://github.comgit//sdbondi/tari-crypto/commit/ea6713b616cbe310697287adfc8ffd68c3c3fcac))
    - Merge pull request #11 from tari-project/use_thiserror ([`5e985a8`](https://github.comgit//sdbondi/tari-crypto/commit/5e985a8f4d7a40e6e79dcb4469607d902f6e6f54))
    - Add a function to the range proof trait ([`2efbe42`](https://github.comgit//sdbondi/tari-crypto/commit/2efbe4236f8ff804b12dfb94ae7478e7359ceb06))
</details>

## v0.7.0 (2020-08-17)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 1 commit contributed to the release.
 - 20 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' where seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Bump version ([`db3596a`](https://github.comgit//sdbondi/tari-crypto/commit/db3596af15f8f3c88a5deba8204a8a7d24e07152))
</details>

## v0.6.0 (2020-07-28)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 1 commit contributed to the release.
 - 12 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' where seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Switch error library to this error ([`91f8b8d`](https://github.comgit//sdbondi/tari-crypto/commit/91f8b8da16c95b0c0fa868d5ac1a171e42a5d2b5))
</details>

## v0.5.0 (2020-07-15)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 5 commits contributed to the release over the course of 9 calendar days.
 - 22 days passed between releases.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 2 unique issues were worked on: [#14](https://github.comgit//sdbondi/tari-crypto/issues/14), [#16](https://github.comgit//sdbondi/tari-crypto/issues/16)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#14](https://github.comgit//sdbondi/tari-crypto/issues/14)**
    - Develop the ScriptCommitment wrapper type. ([`208f94f`](https://github.comgit//sdbondi/tari-crypto/commit/208f94f026f97f3f4dd8af58ce8152ec8c948c13))
 * **[#16](https://github.comgit//sdbondi/tari-crypto/issues/16)**
    - Additional tests ([`8684f88`](https://github.comgit//sdbondi/tari-crypto/commit/8684f882f0d802dc53b698ba9ffc08285bd6bb1e))
 * **Uncategorized**
    - Bump crate version to 0.5.0 ([`2247806`](https://github.comgit//sdbondi/tari-crypto/commit/2247806396d516d1b90a1c6af9265ade43408592))
    - Merge pull request #10 from dunnock/dunnock-dep-update ([`1580d91`](https://github.comgit//sdbondi/tari-crypto/commit/1580d91df2b610174d4553091e641f3972f40c1c))
    - update tari_utilities dependency ([`7f19082`](https://github.comgit//sdbondi/tari-crypto/commit/7f19082da78dae2f0d7d22033efc54e49e0c52b7))
</details>

## v0.4.0 (2020-06-23)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 25 commits contributed to the release over the course of 140 calendar days.
 - 0 commits where understood as [conventional](https://www.conventionalcommits.org).
 - 8 unique issues were worked on: [#1](https://github.comgit//sdbondi/tari-crypto/issues/1), [#15](https://github.comgit//sdbondi/tari-crypto/issues/15), [#3](https://github.comgit//sdbondi/tari-crypto/issues/3), [#4](https://github.comgit//sdbondi/tari-crypto/issues/4), [#5](https://github.comgit//sdbondi/tari-crypto/issues/5), [#6](https://github.comgit//sdbondi/tari-crypto/issues/6), [#7](https://github.comgit//sdbondi/tari-crypto/issues/7), [#8](https://github.comgit//sdbondi/tari-crypto/issues/8)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#1](https://github.comgit//sdbondi/tari-crypto/issues/1)**
    - Fix .circleci config file Merge pull request #1 ([`2fb1e8c`](https://github.comgit//sdbondi/tari-crypto/commit/2fb1e8c67bb2a9009179ba03e08ed0e548c383d9))
 * **[#15](https://github.comgit//sdbondi/tari-crypto/issues/15)**
    - Add test coverage report ([`fc9abeb`](https://github.comgit//sdbondi/tari-crypto/commit/fc9abebf715e2b9ee9e5c4ef162590007d7721b6))
 * **[#3](https://github.comgit//sdbondi/tari-crypto/issues/3)**
    - Add range proofs Merge pull request #3 ([`27b2934`](https://github.comgit//sdbondi/tari-crypto/commit/27b293474d7302f7d833a408717eccf526ba7fdf))
 * **[#4](https://github.comgit//sdbondi/tari-crypto/issues/4)**
    - Export tari_utilities Merge pull request #4 ([`d7e62d1`](https://github.comgit//sdbondi/tari-crypto/commit/d7e62d152ab84f5bbb2bcb7f1725909550317332))
 * **[#5](https://github.comgit//sdbondi/tari-crypto/issues/5)**
    - Add Clippy Github action Merge pull request #5 ([`2f264bf`](https://github.comgit//sdbondi/tari-crypto/commit/2f264bf251ec4af82947b4eb41111b8c6b49d179))
 * **[#6](https://github.comgit//sdbondi/tari-crypto/issues/6)**
    - Fix clippy hints Merge pull request #6 ([`50b3e42`](https://github.comgit//sdbondi/tari-crypto/commit/50b3e42d408ca8e56e3c24332a7368437cb1c440))
 * **[#7](https://github.comgit//sdbondi/tari-crypto/issues/7)**
    - Bump to blake2 v0.8.1 Merge pull request #7 ([`7cf5a11`](https://github.comgit//sdbondi/tari-crypto/commit/7cf5a11261a1a1eb0a35008fc4aa6288072219ca))
 * **[#8](https://github.comgit//sdbondi/tari-crypto/issues/8)**
    - Make Public Key Debug format human readable Merge pull request #8 ([`e9d806d`](https://github.comgit//sdbondi/tari-crypto/commit/e9d806d5d20740f90d331901b7393233a7bb16eb))
 * **Uncategorized**
    - Merge pull request #9 from tari-project/upd_clear_on_drop ([`1600239`](https://github.comgit//sdbondi/tari-crypto/commit/160023921cf439715a432302e34276376a4674ff))
    - Update clear_on_drop ([`4c33ce8`](https://github.comgit//sdbondi/tari-crypto/commit/4c33ce8a02f53aab01caf2ebcce5f0e8a671924a))
    - Make Public Key Debug format human readable ([`85c8381`](https://github.comgit//sdbondi/tari-crypto/commit/85c8381222299e3276c291dece9fbae61a94dba4))
    - Bump to blake2 v0.8.1 ([`5671b99`](https://github.comgit//sdbondi/tari-crypto/commit/5671b993ddaed91eefeb1d8a146baad0ca95313f))
    - Fix clippy hints ([`09d4dd5`](https://github.comgit//sdbondi/tari-crypto/commit/09d4dd513d0cdf4637e180bec525f471af6e838f))
    - Add Security audit and badges ([`eb09eb4`](https://github.comgit//sdbondi/tari-crypto/commit/eb09eb400d882d88e0a72d434868a086486cd5b6))
    - Add Clippy Github action ([`5bbf52c`](https://github.comgit//sdbondi/tari-crypto/commit/5bbf52cbdb10ce0e14ee52ba23d2d0dbc72e2b76))
    - Bump version ([`41834f5`](https://github.comgit//sdbondi/tari-crypto/commit/41834f5531a1ed7b9946d3a1c5e66fb8d4711305))
    - Export tari_utilities ([`be88b14`](https://github.comgit//sdbondi/tari-crypto/commit/be88b1456586b57fd0d4ca74e46491bdaa8e03f6))
    - Merge branch 'master' into range_proof ([`2c59f91`](https://github.comgit//sdbondi/tari-crypto/commit/2c59f915de9bbb63e8689bbb48ccb294fbab7449))
    - Merge pull request #2 from tari-project/commitments_wasm ([`b0ac041`](https://github.comgit//sdbondi/tari-crypto/commit/b0ac0419ffd60b676d7d91d3fc53bcc525889ef8))
    - Add range proofs ([`c3a73e0`](https://github.comgit//sdbondi/tari-crypto/commit/c3a73e0a64a3de9211719ef40fe318974ca8a9bf))
    - WASM commitments ([`306c43a`](https://github.comgit//sdbondi/tari-crypto/commit/306c43aa8585d51827c97963e264002bbcadbf29))
    - Bump crate version ([`c3fb0c9`](https://github.comgit//sdbondi/tari-crypto/commit/c3fb0c97e5b6ffeb71584eb893f18af154ebcffe))
    - Re-export traits from taru_utilities ([`b1cf82f`](https://github.comgit//sdbondi/tari-crypto/commit/b1cf82ffe94beb947eb382aa212f5f74c9832472))
    - Fix .circleci config file ([`db7683b`](https://github.comgit//sdbondi/tari-crypto/commit/db7683b8d6489959ec045b160ac17f0ce72babbc))
    - Port library from tari repo ([`d3c8db2`](https://github.comgit//sdbondi/tari-crypto/commit/d3c8db2514b88fabfdd91a42877ab525ad8d6a81))
</details>

