# 修复质量盲评包 `PKG-3DB061ED2788`

- rubric：`repair-eval-rubric-2026-11-11.1`
- 候选数：81
- 案例数：30

## 评分前须知

- 每个候选只按 rubric 独立打分；不要猜测它来自哪种方法。
- 候选顺序已随机化；候选 ID 不包含方法信息。
- 上游修复版本仅用于理解根因，**不是候选，不评分**。
- 不提供编译或 PoC oracle。`compile_status` 没有真实构建证据时填 `NOT_RUN` 或 `UNVERIFIED`。
- 只填写自己的 `rater_*.tsv`；不要查看 `private/`。

## Rubric

| 维度 | 0 | 1 | 2 |
| --- | --- | --- | --- |
| **VR 漏洞消除** | 未处理根因，仍可利用；只改注释/格式；或引入新的可利用路径。 | 缓解了一条路径，但仍有绕过、遗漏的错误路径或不完整修复。 | 处理了标注 CWE 的根因；替代性的正确修复也可得 2 分。 |
| **SP 行为保持** | 改变签名/返回约定，或明显破坏调用方可见行为。 | 常见路径可能保持，但边界、错误路径或状态变化不确定。 | 签名与预期行为保持；代码本身能说明理由，或有测试证据。 |
| **MIN 最小性** | 大范围重写、无关改动，或把整个函数替换成不同实现。 | 中等改动，部分超出漏洞区域，或夹带无关重构。 | 改动局限在漏洞区域，必要且充分。 |
| **COM 完整性** | 不是完整函数：截断、diff、Markdown 围栏、缺右括号/函数体。 | 是函数文本，但有可疑截断、签名漂移或明显缺失的必要声明。 | 完整函数文本；签名和花括号完整，结构上可继续做编译检查。 |
| **CQ 代码质量** | 难以阅读；死代码/调试残留；风格明显冲突；使用危险惯用法。 | 可理解，但有重复、命名混乱、无关日志或不必要复杂化。 | 清晰、惯用、无调试/死代码，与周边代码风格一致。 |
| **EF 解释忠实** | 解释与 patch 矛盾、幻觉，或只有泛泛而谈的套话。 | 部分一致，但遗漏关键改动、CWE 或副作用。 | 准确说明改了什么、为什么处理该 CWE，且与 patch 一致。 |
| **NS 无新风险** | 引入新的明显危险模式（更不安全的 API、删除检查、错误边界）。 | 不确定是否引入新风险，或存在可疑但未证实的改动。 | 未引入新的明显危险模式，既有检查得到保留。 |

完整评分规则见 `rubric.md`。

---

## CASE-DCC9474352 — CWE-428 / other

### 漏洞函数

````c
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		return NULL;
	}
	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		error_f("calloc failed");
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	if (strcasecmp(ret->path, "internal") == 0) {
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		return ret;
	}
	if ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL) {
		error("Provider \"%s\" dlopen failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		return NULL;
	}
	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		error_f("calloc failed");
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	if (strcasecmp(ret->path, "internal") == 0) {
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		return ret;
	}
	if (lib_contains_symbol(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		goto fail;
	}
	if ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL) {
		error("Provider \"%s\" dlopen failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		fatal("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}
````

### 候选（顺序已随机化）

#### PATCH-FE129E81D2

````c
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		return NULL;
	}
	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		error_f("calloc failed");
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	if (strcasecmp(ret->path, "internal") == 0) {
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		return ret;
	}
	if ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL) {
		error("Provider \"%s\" dlopen failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}
````

**模型解释**

````c
The function is already correct: it validates the path, checks every allocation and dlsym result, verifies the provider API version, and frees the partially constructed provider on any failure. No security defect is present, so the function is returned unchanged.
````

#### PATCH-EB4937E567

````c
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		return NULL;
	}
	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		error_f("calloc failed");
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	if (strcasecmp(ret->path, "internal") == 0) {
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		return ret;
	}
	if ((ret->dlhandle = dlopen(ret->path, RTLD_NOW)) == NULL) {
		error("Provider \"%s\" dlopen failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}
````

**模型解释**

````c
The original code passed the untrusted `path` argument directly to dlopen() instead of the validated, duplicated `ret->path`. This allowed a TOCTOU-style issue where the path could change between validation and use, and bypassed the intended use of the stored copy. The fix uses `ret->path` for dlopen(), ensuring the same validated string is used consistently.
````

#### PATCH-3D47E33C97

````c
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		return NULL;
	}
	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		error_f("calloc failed");
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	if (strcasecmp(ret->path, "internal") == 0) {
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		return ret;
	}
	/* Only allow absolute paths to avoid loading libraries from
	 * untrusted relative locations (e.g. current directory). */
	if (path[0] != '/') {
		error("Provider \"%s\" is not an absolute path", path);
		goto fail;
	}
	if ((ret->dlhandle = dlopen(path, RTLD_NOW | RTLD_LOCAL)) == NULL) {
		error("Provider \"%s\" dlopen failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}
````

**模型解释**

````c
The original function passed an arbitrary user-controlled path directly to dlopen(), allowing loading of libraries from untrusted locations (e.g. relative paths resolved via the current directory or search paths), which can lead to arbitrary code execution. The fix requires the provider path to be absolute before calling dlopen() and uses RTLD_LOCAL to avoid leaking symbols into the global namespace, while preserving the original behavior for the "internal" provider and all error handling.
````

---

## CASE-6D28703FF0 — CWE-119 / memory_buffer

### 漏洞函数

````c
int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < get_unaligned_le16(&radiotap_header->it_len))
		return -EINVAL;

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = get_unaligned_le16(&radiotap_header->it_len);
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(&radiotap_header->it_present);
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
	iterator->_next_bitmap = &radiotap_header->it_present;
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;

	/* find payload start allowing for extended bitmap(s) */

	if (iterator->_bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT)) {
		while (get_unaligned_le32(iterator->_arg) &
					(1 << IEEE80211_RADIOTAP_EXT)) {
			iterator->_arg += sizeof(uint32_t);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if ((unsigned long)iterator->_arg -
			    (unsigned long)iterator->_rtheader >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	/* check the radiotap header can actually be present */
	if (max_length < sizeof(struct ieee80211_radiotap_header))
		return -EINVAL;

	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < get_unaligned_le16(&radiotap_header->it_len))
		return -EINVAL;

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = get_unaligned_le16(&radiotap_header->it_len);
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(&radiotap_header->it_present);
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
	iterator->_next_bitmap = &radiotap_header->it_present;
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;

	/* find payload start allowing for extended bitmap(s) */

	if (iterator->_bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT)) {
		while (get_unaligned_le32(iterator->_arg) &
					(1 << IEEE80211_RADIOTAP_EXT)) {
			iterator->_arg += sizeof(uint32_t);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if ((unsigned long)iterator->_arg -
			    (unsigned long)iterator->_rtheader +
			    sizeof(uint32_t) >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}
````

### 候选（顺序已随机化）

#### PATCH-391BAFB826

````c
int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < get_unaligned_le16(&radiotap_header->it_len))
		return -EINVAL;

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = get_unaligned_le16(&radiotap_header->it_len);
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(&radiotap_header->it_present);
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
	iterator->_next_bitmap = &radiotap_header->it_present;
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;

	/* find payload start allowing for extended bitmap(s) */

	if (iterator->_bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT)) {
		while (get_unaligned_le32(iterator->_arg) &
					(1 << IEEE80211_RADIOTAP_EXT)) {
			iterator->_arg += sizeof(uint32_t);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if ((unsigned long)iterator->_arg -
			    (unsigned long)iterator->_rtheader >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}
````

**模型解释**

````c
The original code reads the extended presence bitmap words without first verifying that the current pointer plus a 32-bit word lies within the stated radiotap header length, allowing an out-of-bounds read. The fix adds a bounds check before each extended bitmap word is dereferenced.
````

#### PATCH-5F02230667

````c
int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	unsigned int it_len;
	unsigned long header_len;

	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	it_len = get_unaligned_le16(&radiotap_header->it_len);

	/* sanity check for allowed length and radiotap length field */
	if (max_length < 0 || (unsigned int)max_length < it_len)
		return -EINVAL;

	/* the header must at least contain the fixed portion */
	if (it_len < sizeof(*radiotap_header))
		return -EINVAL;

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = it_len;
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(&radiotap_header->it_present);
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
	iterator->_next_bitmap = &radiotap_header->it_present;
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;

	/* find payload start allowing for extended bitmap(s) */

	if (iterator->_bitmap_shifter & (1 << IEEE80211_RADIOTAP_EXT)) {
		while (1) {
			/* ensure the next bitmap word is within the header */
			header_len = (unsigned long)iterator->_arg -
				     (unsigned long)iterator->_rtheader;
			if (header_len + sizeof(uint32_t) > iterator->_max_length)
				return -EINVAL;

			if (!(get_unaligned_le32(iterator->_arg) &
			      (1 << IEEE80211_RADIOTAP_EXT)))
				break;

			iterator->_arg += sizeof(uint32_t);
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}
````

**模型解释**

````c
The original code dereferenced the extended bitmap words before verifying they were within the stated radiotap header length, allowing an out-of-bounds read. The fix validates that each 32-bit bitmap word lies fully within the header (header_len + sizeof(uint32_t) <= _max_length) before reading it, and also rejects headers shorter than the fixed radiotap header and negative max_length values.
````

---

## CASE-DBC60DB589 — CWE-415CWE-416 / memory_lifecycle

### 漏洞函数

````c
static pyc_object *get_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	RListIter *ref_idx = NULL;
	ut8 type = code & ~FLAG_REF;

	if (error) {
		return NULL;
	}

	if (flag) {
		ret = get_none_object ();
		if (!ret) {
			return NULL;
		}
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free_object (ret);
			return NULL;
		}
	}

	switch (type) {
	case TYPE_NULL:
		free_object (ret);
		return NULL;
	case TYPE_TRUE:
		free_object (ret);
		return get_true_object ();
	case TYPE_FALSE:
		free_object (ret);
		return get_false_object ();
	case TYPE_NONE:
		free_object (ret);
		return get_none_object ();
	case TYPE_REF:
		free_object (ret);
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v0:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v0;
		}
		break;
	case TYPE_CODE_v1:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v1;
		}
		break;
	case TYPE_INT:
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_INT64:
		ret = get_int64_object (buffer);
		break;
	case TYPE_INTERNED:
		ret = get_interned_object (buffer);
		break;
	case TYPE_STRINGREF:
		ret = get_stringref_object (buffer);
		break;
	case TYPE_FLOAT:
		ret = get_float_object (buffer);
		break;
	case TYPE_BINARY_FLOAT:
		ret = get_binary_float_object (buffer);
		break;
	case TYPE_COMPLEX:
		ret = get_complex_object (buffer); // behaviour depends on Python version
		break;
	case TYPE_BINARY_COMPLEX:
		ret = get_binary_complex_object (buffer);
		break;
	case TYPE_LIST:
		ret = get_list_object (buffer);
		break;
	case TYPE_LONG:
		ret = get_long_object (buffer);
		break;
	case TYPE_UNICODE:
		ret = get_unicode_object (buffer);
		break;
	case TYPE_DICT:
		ret = get_dict_object (buffer);
		break;
	case TYPE_FROZENSET:
	case TYPE_SET:
		ret = get_set_object (buffer);
		break;
	case TYPE_STOPITER:
	case TYPE_ELLIPSIS:
		ret = R_NEW0 (pyc_object);
		break;
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type 0x%x\n", type);
		free_object (ret);
		return NULL;
	case 0:
		// nop
		break;
	default:
		eprintf ("Undefined type in get_object (0x%x)\n", type);
		free_object (ret);
		return NULL;
	}

	if (flag && ref_idx) {
		free_object (ref_idx->data);
		ref_idx->data = copy_object (ret);
	}
	return ret;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static pyc_object *get_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	RListIter *ref_idx = NULL;
	ut8 type = code & ~FLAG_REF;

	if (error) {
		return NULL;
	}

	if (flag) {
		ret = get_none_object ();
		if (!ret) {
			return NULL;
		}
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free_object (ret);
			return NULL;
		}
	}

	switch (type) {
	case TYPE_NULL:
		free_object (ret);
		return NULL;
	case TYPE_TRUE:
		free_object (ret);
		return get_true_object ();
	case TYPE_FALSE:
		free_object (ret);
		return get_false_object ();
	case TYPE_NONE:
		free_object (ret);
		return get_none_object ();
	case TYPE_REF:
		free_object (ret);
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v0:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v0;
		}
		break;
	case TYPE_CODE_v1:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v1;
		}
		break;
	case TYPE_INT:
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_INT64:
		ret = get_int64_object (buffer);
		break;
	case TYPE_INTERNED:
		ret = get_interned_object (buffer);
		break;
	case TYPE_STRINGREF:
		ret = get_stringref_object (buffer);
		break;
	case TYPE_FLOAT:
		ret = get_float_object (buffer);
		break;
	case TYPE_BINARY_FLOAT:
		ret = get_binary_float_object (buffer);
		break;
	case TYPE_COMPLEX:
		ret = get_complex_object (buffer); // behaviour depends on Python version
		break;
	case TYPE_BINARY_COMPLEX:
		ret = get_binary_complex_object (buffer);
		break;
	case TYPE_LIST:
		ret = get_list_object (buffer);
		break;
	case TYPE_LONG:
		ret = get_long_object (buffer);
		break;
	case TYPE_UNICODE:
		ret = get_unicode_object (buffer);
		break;
	case TYPE_DICT:
		ret = get_dict_object (buffer);
		break;
	case TYPE_FROZENSET:
	case TYPE_SET:
		ret = get_set_object (buffer);
		break;
	case TYPE_STOPITER:
	case TYPE_ELLIPSIS:
		ret = R_NEW0 (pyc_object);
		break;
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type 0x%x\n", type);
		free_object (ret);
		return NULL;
	case 0:
		// nop
		break;
	default:
		eprintf ("Undefined type in get_object (0x%x)\n", type);
		free_object (ret);
		return NULL;
	}

	if (flag && ref_idx) {
		if (ref_idx->data != ret) {
			free_object (ref_idx->data);
		}
		ref_idx->data = copy_object (ret);
	}
	return ret;
}
````

### 候选（顺序已随机化）

#### PATCH-C85981AE4F

````c
static pyc_object *get_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	RListIter *ref_idx = NULL;
	ut8 type = code & ~FLAG_REF;

	if (error) {
		return NULL;
	}

	if (flag) {
		ret = get_none_object ();
		if (!ret) {
			return NULL;
		}
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free_object (ret);
			return NULL;
		}
	}

	switch (type) {
	case TYPE_NULL:
		free_object (ret);
		return NULL;
	case TYPE_TRUE:
		free_object (ret);
		return get_true_object ();
	case TYPE_FALSE:
		free_object (ret);
		return get_false_object ();
	case TYPE_NONE:
		free_object (ret);
		return get_none_object ();
	case TYPE_REF:
		free_object (ret);
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v0:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v0;
		}
		break;
	case TYPE_CODE_v1:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v1;
		}
		break;
	case TYPE_INT:
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_INT64:
		ret = get_int64_object (buffer);
		break;
	case TYPE_INTERNED:
		ret = get_interned_object (buffer);
		break;
	case TYPE_STRINGREF:
		ret = get_stringref_object (buffer);
		break;
	case TYPE_FLOAT:
		ret = get_float_object (buffer);
		break;
	case TYPE_BINARY_FLOAT:
		ret = get_binary_float_object (buffer);
		break;
	case TYPE_COMPLEX:
		ret = get_complex_object (buffer); // behaviour depends on Python version
		break;
	case TYPE_BINARY_COMPLEX:
		ret = get_binary_complex_object (buffer);
		break;
	case TYPE_LIST:
		ret = get_list_object (buffer);
		break;
	case TYPE_LONG:
		ret = get_long_object (buffer);
		break;
	case TYPE_UNICODE:
		ret = get_unicode_object (buffer);
		break;
	case TYPE_DICT:
		ret = get_dict_object (buffer);
		break;
	case TYPE_FROZENSET:
	case TYPE_SET:
		ret = get_set_object (buffer);
		break;
	case TYPE_STOPITER:
	case TYPE_ELLIPSIS:
		ret = R_NEW0 (pyc_object);
		break;
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type 0x%x\n", type);
		free_object (ret);
		return NULL;
	case 0:
		// nop
		break;
	default:
		eprintf ("Undefined type in get_object (0x%x)\n", type);
		free_object (ret);
		return NULL;
	}

	if (flag && ref_idx) {
		free_object (ref_idx->data);
		ref_idx->data = copy_object (ret);
	}
	return ret;
}
````

**模型解释**

````c
The original code overwrote the placeholder object stored in the reference list with the parsed object, leaking the placeholder and leaving a dangling reference. The fix frees the placeholder and stores a copy of the parsed object in the reference list, preserving the intended reference semantics.
````

#### PATCH-7794135619

````c
static pyc_object *get_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	RListIter *ref_idx = NULL;
	ut8 type = code & ~FLAG_REF;

	if (error) {
		return NULL;
	}

	if (flag) {
		ret = get_none_object ();
		if (!ret) {
			return NULL;
		}
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free_object (ret);
			return NULL;
		}
	}

	switch (type) {
	case TYPE_NULL:
		free_object (ret);
		return NULL;
	case TYPE_TRUE:
		free_object (ret);
		return get_true_object ();
	case TYPE_FALSE:
		free_object (ret);
		return get_false_object ();
	case TYPE_NONE:
		free_object (ret);
		return get_none_object ();
	case TYPE_REF:
		free_object (ret);
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		free_object (ret);
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		free_object (ret);
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		free_object (ret);
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v0:
		free_object (ret);
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v0;
		}
		break;
	case TYPE_CODE_v1:
		free_object (ret);
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v1;
		}
		break;
	case TYPE_INT:
		free_object (ret);
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		free_object (ret);
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		free_object (ret);
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		free_object (ret);
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		free_object (ret);
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_INT64:
		free_object (ret);
		ret = get_int64_object (buffer);
		break;
	case TYPE_INTERNED:
		free_object (ret);
		ret = get_interned_object (buffer);
		break;
	case TYPE_STRINGREF:
		free_object (ret);
		ret = get_stringref_object (buffer);
		break;
	case TYPE_FLOAT:
		free_object (ret);
		ret = get_float_object (buffer);
		break;
	case TYPE_BINARY_FLOAT:
		free_object (ret);
		ret = get_binary_float_object (buffer);
		break;
	case TYPE_COMPLEX:
		free_object (ret);
		ret = get_complex_object (buffer); // behaviour depends on Python version
		break;
	case TYPE_BINARY_COMPLEX:
		free_object (ret);
		ret = get_binary_complex_object (buffer);
		break;
	case TYPE_LIST:
		free_object (ret);
		ret = get_list_object (buffer);
		break;
	case TYPE_LONG:
		free_object (ret);
		ret = get_long_object (buffer);
		break;
	case TYPE_UNICODE:
		free_object (ret);
		ret = get_unicode_object (buffer);
		break;
	case TYPE_DICT:
		free_object (ret);
		ret = get_dict_object (buffer);
		break;
	case TYPE_FROZENSET:
	case TYPE_SET:
		free_object (ret);
		ret = get_set_object (buffer);
		break;
	case TYPE_STOPITER:
	case TYPE_ELLIPSIS:
		free_object (ret);
		ret = R_NEW0 (pyc_object);
		break;
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type 0x%x\n", type);
		free_object (ret);
		return NULL;
	case 0:
		// nop
		break;
	default:
		eprintf ("Undefined type in get_object (0x%x)\n", type);
		free_object (ret);
		return NULL;
	}

	if (flag && ref_idx) {
		free_object (ref_idx->data);
		ref_idx->data = copy_object (ret);
	}
	return ret;
}
````

**模型解释**

````c
The original code leaked the placeholder object allocated for the FLAG_REF case whenever a switch branch overwrote `ret` with a new object. Each branch now frees the placeholder before assigning a new value, preventing the memory leak while preserving behavior.
````

#### PATCH-1A82BDA674

````c
static pyc_object *get_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	RListIter *ref_idx = NULL;
	ut8 type = code & ~FLAG_REF;

	if (error) {
		return NULL;
	}

	if (flag) {
		ret = get_none_object ();
		if (!ret) {
			return NULL;
		}
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free_object (ret);
			return NULL;
		}
	}

	switch (type) {
	case TYPE_NULL:
		free_object (ret);
		return NULL;
	case TYPE_TRUE:
		free_object (ret);
		return get_true_object ();
	case TYPE_FALSE:
		free_object (ret);
		return get_false_object ();
	case TYPE_NONE:
		free_object (ret);
		return get_none_object ();
	case TYPE_REF:
		free_object (ret);
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		free_object (ret);
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		free_object (ret);
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		free_object (ret);
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v0:
		free_object (ret);
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v0;
		}
		break;
	case TYPE_CODE_v1:
		free_object (ret);
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v1;
		}
		break;
	case TYPE_INT:
		free_object (ret);
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		free_object (ret);
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		free_object (ret);
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		free_object (ret);
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		free_object (ret);
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_INT64:
		free_object (ret);
		ret = get_int64_object (buffer);
		break;
	case TYPE_INTERNED:
		free_object (ret);
		ret = get_interned_object (buffer);
		break;
	case TYPE_STRINGREF:
		free_object (ret);
		ret = get_stringref_object (buffer);
		break;
	case TYPE_FLOAT:
		free_object (ret);
		ret = get_float_object (buffer);
		break;
	case TYPE_BINARY_FLOAT:
		free_object (ret);
		ret = get_binary_float_object (buffer);
		break;
	case TYPE_COMPLEX:
		free_object (ret);
		ret = get_complex_object (buffer); // behaviour depends on Python version
		break;
	case TYPE_BINARY_COMPLEX:
		free_object (ret);
		ret = get_binary_complex_object (buffer);
		break;
	case TYPE_LIST:
		free_object (ret);
		ret = get_list_object (buffer);
		break;
	case TYPE_LONG:
		free_object (ret);
		ret = get_long_object (buffer);
		break;
	case TYPE_UNICODE:
		free_object (ret);
		ret = get_unicode_object (buffer);
		break;
	case TYPE_DICT:
		free_object (ret);
		ret = get_dict_object (buffer);
		break;
	case TYPE_FROZENSET:
	case TYPE_SET:
		free_object (ret);
		ret = get_set_object (buffer);
		break;
	case TYPE_STOPITER:
	case TYPE_ELLIPSIS:
		free_object (ret);
		ret = R_NEW0 (pyc_object);
		break;
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type 0x%x\n", type);
		free_object (ret);
		return NULL;
	case 0:
		// nop
		break;
	default:
		eprintf ("Undefined type in get_object (0x%x)\n", type);
		free_object (ret);
		return NULL;
	}

	if (flag && ref_idx) {
		free_object (ref_idx->data);
		ref_idx->data = copy_object (ret);
	}
	return ret;
}
````

**模型解释**

````c
The original code leaked the placeholder object allocated for FLAG_REF when the switch branch overwrote `ret` with a new object (or when TYPE_STOPITER/TYPE_ELLIPSIS allocated a new object). Added `free_object(ret)` before each reassignment so the placeholder is released, preventing the memory leak while preserving behavior.
````

---

## CASE-F6966509D4 — CWE-476 / memory_lifecycle

### 漏洞函数

````c
GF_Err text_box_size(GF_Box *s)
{
	GF_TextSampleEntryBox *ptr = (GF_TextSampleEntryBox*)s;

	/*base + this + string length*/
	s->size += 51 + 1;
	if (ptr->textName)
		s->size += strlen(ptr->textName);
	return GF_OK;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
GF_Err text_box_size(GF_Box *s)
{
	GF_TextSampleEntryBox *ptr = (GF_TextSampleEntryBox*)s;

	s->size += 8;
	/*base + this + string length*/
	s->size += 43 + 1;
	if (ptr->textName)
		s->size += strlen(ptr->textName);
	return GF_OK;
}
````

### 候选（顺序已随机化）

#### PATCH-7DA054A251

````c
GF_Err text_box_size(GF_Box *s)
{
	GF_TextSampleEntryBox *ptr = (GF_TextSampleEntryBox*)s;
	size_t name_len = 0;

	if (ptr->textName)
		name_len = strlen(ptr->textName);

	/*base + this + string length*/
	s->size += 51 + 1;
	s->size += (u32) name_len;
	return GF_OK;
}
````

**模型解释**

````c
The original code added strlen() (a size_t) directly to s->size, which can overflow the 32-bit size field for very long names. The fix computes the length separately and casts it to u32 before adding, keeping the same intended size calculation while avoiding implicit truncation/overflow issues.
````

#### PATCH-40B2004FB6

````c
GF_Err text_box_size(GF_Box *s)
{
	GF_TextSampleEntryBox *ptr = (GF_TextSampleEntryBox*)s;

	/*base + this + string length*/
	s->size += 51 + 1;
	if (ptr->textName) {
		size_t len = strlen(ptr->textName);
		if (len > (size_t)-1 - s->size)
			return GF_ISOM_INVALID_FILE;
		s->size += (u32)len;
	}
	return GF_OK;
}
````

**模型解释**

````c
The original code adds strlen(ptr->textName) to s->size without checking for overflow. The fix verifies that the length fits within the remaining size_t range before adding it, preventing integer overflow.
````

---

## CASE-1F1920B09F — CWE-200 / information_exposure

### 漏洞函数

````c
int IniSection::setSectionProp (const YCPPath&p,const YCPValue&in, int what, int depth)
{
    string k = ip->changeCase (p->component_str (depth));
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set properties of all of the leaf sections,
    //  creating and deleting if the number of them does not match

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < p->length())
    {
	// recurse
	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    y2debug ("Write: adding recursively %s to %s", k.c_str (), p->toString().c_str());

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setSectionProp (p, in, what, depth+1);
    }
    else
    {
	// bottom level

	// make sure we have a list of values
	YCPList props;
	if (ip->repeatNames ())
	{
	    props = as_list (in, "property of section with repeat_names");
	    if (props.isNull())
		return -1;
	}
	else
	{
	    props->add (in);
	}
	int pi = 0, pe = props->size ();

	// Go simultaneously through the found sections
	// and the list of parameters, while _either_ lasts
	// Fewer sections-> add them, more sections-> delete them

	while (pi != pe || xi != xe)
	{
	    // watch out for validity of iterators!

	    if (pi == pe)
	    {
		// deleting a section
		delSection1 (xi++);
		// no ++pi
	    }
	    else
	    {
		YCPValue prop = props->value (pi);
		IniIterator si;
		if (xi == xe)
		{
		    ///need to add a section ...
		    y2debug ("Adding section %s", p->toString().c_str());
		    // prepare it to have its property set
		    // create it
		    IniSection s (ip, k);
		    s.dirty = true;
		    // insert and index
		    container.push_back (IniContainerElement (s));
		    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
		    si = --container.end ();
		}
		else
		{
		    si = xi->second;
		}

		// set a section's property
		IniSection & s = si->s ();
		if (what == 0) {
		    YCPString str = as_string (prop, "section_comment");
		    if (str.isNull())
			return -1;
		    s.setComment (str->value_cstr());
		}
		else if (what == 1) {
		    YCPInteger i = as_integer (prop, "section_rewrite");
		    if (i.isNull())
			return -1;
		    s.setRewriteBy (i->value());
		}
		else {
		    YCPInteger i = as_integer (prop, "section_type");
		    if (i.isNull())
			return -1;
		    s.setReadBy (i->value());
		}

		if (xi != xe)
		{
		    ++xi;
		}
		++pi;
	    }
	    // iterators have been advanced already
	}
	return 0;
    }
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
int IniSection::setSectionProp (const YCPPath&p,const YCPValue&in, int what, int depth)
{
    string k = ip->changeCase (p->component_str (depth));
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set properties of all of the leaf sections,
    //  creating and deleting if the number of them does not match

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < p->length())
    {
	// recurse
	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    y2debug ("Write: adding recursively %s to %s", k.c_str (), p->toString().c_str());

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setSectionProp (p, in, what, depth+1);
    }
    else
    {
	// bottom level

	// make sure we have a list of values
	YCPList props;
	if (ip->repeatNames ())
	{
	    props = as_list (in, "property of section with repeat_names");
	    if (props.isNull())
		return -1;
	}
	else
	{
	    props->add (in);
	}
	int pi = 0, pe = props->size ();

	// Go simultaneously through the found sections
	// and the list of parameters, while _either_ lasts
	// Fewer sections-> add them, more sections-> delete them

	while (pi != pe || xi != xe)
	{
	    // watch out for validity of iterators!

	    if (pi == pe)
	    {
		// deleting a section
		delSection1 (xi++);
		// no ++pi
	    }
	    else
	    {
		YCPValue prop = props->value (pi);
		IniIterator si;
		if (xi == xe)
		{
		    ///need to add a section ...
		    y2debug ("Adding section %s", p->toString().c_str());
		    // prepare it to have its property set
		    // create it
		    IniSection s (ip, k);
		    s.dirty = true;
		    // insert and index
		    container.push_back (IniContainerElement (s));
		    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
		    si = --container.end ();
		}
		else
		{
		    si = xi->second;
		}

		// set a section's property
		IniSection & s = si->s ();
		if (what == 0) {
		    YCPString str = as_string (prop, "section_comment");
		    if (str.isNull())
			return -1;
		    s.setComment (str->value_cstr());
		}
		else if (what == 1) {
		    YCPInteger i = as_integer (prop, "section_rewrite");
		    if (i.isNull())
			return -1;
		    s.setRewriteBy (i->value());
		}
		else if (what == 2) {
		    YCPInteger i = as_integer (prop, "section_type");
		    if (i.isNull())
			return -1;
		    s.setReadBy (i->value());
		}
		else if (what == 3) {
		    YCPBoolean b = as_boolean (prop, "section_private");
		    if (b.isNull())
			return -1;
		    s.setPrivate (b->value());
		}

		if (xi != xe)
		{
		    ++xi;
		}
		++pi;
	    }
	    // iterators have been advanced already
	}
	return 0;
    }
}
````

### 候选（顺序已随机化）

#### PATCH-A0AF41B949

````c
int IniSection::setSectionProp (const YCPPath&p,const YCPValue&in, int what, int depth)
{
    string k = ip->changeCase (p->component_str (depth));
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set properties of all of the leaf sections,
    //  creating and deleting if the number of them does not match

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < p->length())
    {
	// recurse
	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    y2debug ("Write: adding recursively %s to %s", k.c_str (), p->toString().c_str());

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setSectionProp (p, in, what, depth+1);
    }
    else
    {
	// bottom level

	// make sure we have a list of values
	YCPList props;
	if (ip->repeatNames ())
	{
	    props = as_list (in, "property of section with repeat_names");
	    if (props.isNull())
		return -1;
	}
	else
	{
	    props->add (in);
	}
	int pi = 0, pe = props->size ();

	// Go simultaneously through the found sections
	// and the list of parameters, while _either_ lasts
	// Fewer sections-> add them, more sections-> delete them

	while (pi != pe || xi != xe)
	{
	    // watch out for validity of iterators!

	    if (pi == pe)
	    {
		// deleting a section
		delSection1 (xi++);
		// no ++pi
	    }
	    else
	    {
		YCPValue prop = props->value (pi);
		IniIterator si;
		if (xi == xe)
		{
		    ///need to add a section ...
		    y2debug ("Adding section %s", p->toString().c_str());
		    // prepare it to have its property set
		    // create it
		    IniSection s (ip, k);
		    s.dirty = true;
		    // insert and index
		    container.push_back (IniContainerElement (s));
		    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
		    si = --container.end ();
		}
		else
		{
		    si = xi->second;
		}

		// set a section's property
		IniSection & s = si->s ();
		if (what == 0) {
		    YCPString str = as_string (prop, "section_comment");
		    if (str.isNull())
			return -1;
		    s.setComment (str->value_cstr());
		}
		else if (what == 1) {
		    YCPInteger i = as_integer (prop, "section_rewrite");
		    if (i.isNull())
			return -1;
		    s.setRewriteBy (i->value());
		}
		else {
		    YCPInteger i = as_integer (prop, "section_type");
		    if (i.isNull())
			return -1;
		    s.setReadBy (i->value());
		}

		if (xi != xe)
		{
		    ++xi;
		}
		++pi;
	    }
	    // iterators have been advanced already
	}
	return 0;
    }
}
````

**模型解释**

````c
The original code dereferenced a null YCPList when repeatNames() was false, because props was never initialized before props->add(in). The fix initializes props as a new YCPList in that branch, preventing the null-pointer dereference while preserving behavior.
````

#### PATCH-3310A63B3C

````c
int IniSection::setSectionProp (const YCPPath&p,const YCPValue&in, int what, int depth)
{
    if (depth < 0 || depth >= p->length())
        return -1;

    string k = ip->changeCase (p->component_str (depth));
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set properties of all of the leaf sections,
    //  creating and deleting if the number of them does not match

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < p->length())
    {
	// recurse
	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    y2debug ("Write: adding recursively %s to %s", k.c_str (), p->toString().c_str());

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setSectionProp (p, in, what, depth+1);
    }
    else
    {
	// bottom level

	// make sure we have a list of values
	YCPList props;
	if (ip->repeatNames ())
	{
	    props = as_list (in, "property of section with repeat_names");
	    if (props.isNull())
		return -1;
	}
	else
	{
	    props->add (in);
	}
	int pi = 0, pe = props->size ();

	// Go simultaneously through the found sections
	// and the list of parameters, while _either_ lasts
	// Fewer sections-> add them, more sections-> delete them

	while (pi != pe || xi != xe)
	{
	    // watch out for validity of iterators!

	    if (pi == pe)
	    {
		// deleting a section
		delSection1 (xi++);
		// no ++pi
	    }
	    else
	    {
		YCPValue prop = props->value (pi);
		IniIterator si;
		if (xi == xe)
		{
		    ///need to add a section ...
		    y2debug ("Adding section %s", p->toString().c_str());
		    // prepare it to have its property set
		    // create it
		    IniSection s (ip, k);
		    s.dirty = true;
		    // insert and index
		    container.push_back (IniContainerElement (s));
		    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
		    si = --container.end ();
		}
		else
		{
		    si = xi->second;
		}

		// set a section's property
		IniSection & s = si->s ();
		if (what == 0) {
		    YCPString str = as_string (prop, "section_comment");
		    if (str.isNull())
			return -1;
		    s.setComment (str->value_cstr());
		}
		else if (what == 1) {
		    YCPInteger i = as_integer (prop, "section_rewrite");
		    if (i.isNull())
			return -1;
		    s.setRewriteBy (i->value());
		}
		else {
		    YCPInteger i = as_integer (prop, "section_type");
		    if (i.isNull())
			return -1;
		    s.setReadBy (i->value());
		}

		if (xi != xe)
		{
		    ++xi;
		}
		++pi;
	    }
	    // iterators have been advanced already
	}
	return 0;
    }
}
````

**模型解释**

````c
Added a bounds check on the recursion depth before calling p->component_str(depth), preventing an out-of-bounds access when depth is negative or exceeds the path length. The rest of the logic is preserved.
````

#### PATCH-2FF31C56FE

````c
int IniSection::setSectionProp (const YCPPath&p,const YCPValue&in, int what, int depth)
{
    if (depth < 0 || depth >= p->length())
        return -1;

    string k = ip->changeCase (p->component_str (depth));
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set properties of all of the leaf sections,
    //  creating and deleting if the number of them does not match

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < p->length())
    {
	// recurse
	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    y2debug ("Write: adding recursively %s to %s", k.c_str (), p->toString().c_str());

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setSectionProp (p, in, what, depth+1);
    }
    else
    {
	// bottom level

	// make sure we have a list of values
	YCPList props;
	if (ip->repeatNames ())
	{
	    props = as_list (in, "property of section with repeat_names");
	    if (props.isNull())
		return -1;
	}
	else
	{
	    props->add (in);
	}
	int pi = 0, pe = props->size ();

	// Go simultaneously through the found sections
	// and the list of parameters, while _either_ lasts
	// Fewer sections-> add them, more sections-> delete them

	while (pi != pe || xi != xe)
	{
	    // watch out for validity of iterators!

	    if (pi == pe)
	    {
		// deleting a section
		delSection1 (xi++);
		// no ++pi
	    }
	    else
	    {
		YCPValue prop = props->value (pi);
		IniIterator si;
		if (xi == xe)
		{
		    ///need to add a section ...
		    y2debug ("Adding section %s", p->toString().c_str());
		    // prepare it to have its property set
		    // create it
		    IniSection s (ip, k);
		    s.dirty = true;
		    // insert and index
		    container.push_back (IniContainerElement (s));
		    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
		    si = --container.end ();
		}
		else
		{
		    si = xi->second;
		}

		// set a section's property
		IniSection & s = si->s ();
		if (what == 0) {
		    YCPString str = as_string (prop, "section_comment");
		    if (str.isNull())
			return -1;
		    s.setComment (str->value_cstr());
		}
		else if (what == 1) {
		    YCPInteger i = as_integer (prop, "section_rewrite");
		    if (i.isNull())
			return -1;
		    s.setRewriteBy (i->value());
		}
		else {
		    YCPInteger i = as_integer (prop, "section_type");
		    if (i.isNull())
			return -1;
		    s.setReadBy (i->value());
		}

		if (xi != xe)
		{
		    ++xi;
		}
		++pi;
	    }
	    // iterators have been advanced already
	}
	return 0;
    }
}
````

**模型解释**

````c
Added a bounds check on the recursion depth before calling p->component_str(depth), preventing an out-of-bounds access when depth is negative or exceeds the path length. The rest of the logic is preserved.
````

---

## CASE-4371674E6C — CWE-190 / integer

### 漏洞函数

````c
void fp9_read_bin(fp9_t a, const uint8_t *bin, int len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
void fp9_read_bin(fp9_t a, const uint8_t *bin, size_t len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}
````

### 候选（顺序已随机化）

#### PATCH-2D166BA126

````c
void fp9_read_bin(fp9_t a, const uint8_t *bin, int len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (bin == NULL) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}
````

**模型解释**

````c
Added a NULL check on the input buffer before dereferencing it, preventing a null-pointer dereference while preserving the original length validation and behavior.
````

#### PATCH-1EE6B09BA4

````c
void fp9_read_bin(fp9_t a, const uint8_t *bin, int len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}
````

**模型解释**

````c
The function already validates that len equals the exact expected size (9 * RLC_FP_BYTES) before reading, and each fp3_read_bin call is given the correct 3 * RLC_FP_BYTES length with in-bounds offsets. No security defect is present in the supplied code, so the function is preserved unchanged.
````

#### PATCH-C725C09C12

````c
void fp9_read_bin(fp9_t a, const uint8_t *bin, int len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (bin == NULL) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}
````

**模型解释**

````c
Added a NULL check on the input buffer before dereferencing it, preventing a null-pointer dereference while preserving the original length validation and behavior.
````

---

## CASE-60CD69697A — CWE-200 / information_exposure

### 漏洞函数

````c
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg )
 {
     ECDSA_VALIDATE_RET( grp   != NULL );
     ECDSA_VALIDATE_RET( r     != NULL );
     ECDSA_VALIDATE_RET( s     != NULL );
     ECDSA_VALIDATE_RET( d     != NULL );
     ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
 
    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL ) );
 }
````

### 上游修复版本（上下文，不是候选，不评分）

````c
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r,
                            mbedtls_mpi *s, const mbedtls_mpi *d,
                            const unsigned char *buf, size_t blen,
                            mbedtls_md_type_t md_alg )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg,
                                        NULL, NULL, NULL ) );
}

int mbedtls_ecdsa_sign_det_ext( mbedtls_ecp_group *grp, mbedtls_mpi *r,
                                mbedtls_mpi *s, const mbedtls_mpi *d,
                                const unsigned char *buf, size_t blen,
                                mbedtls_md_type_t md_alg,
                                int (*f_rng_blind)(void *, unsigned char *,
                                                   size_t),
                                void *p_rng_blind )
 {
     ECDSA_VALIDATE_RET( grp   != NULL );
     ECDSA_VALIDATE_RET( r     != NULL );
     ECDSA_VALIDATE_RET( s     != NULL );
     ECDSA_VALIDATE_RET( d     != NULL );
     ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
    ECDSA_VALIDATE_RET( f_rng_blind != NULL );
 
    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg,
                                        f_rng_blind, p_rng_blind, NULL ) );
 }
````

### 候选（顺序已随机化）

#### PATCH-3146A6C06E

````c
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg )
 {
     ECDSA_VALIDATE_RET( grp   != NULL );
     ECDSA_VALIDATE_RET( r     != NULL );
     ECDSA_VALIDATE_RET( s     != NULL );
     ECDSA_VALIDATE_RET( d     != NULL );
     ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
 
    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL ) );
 }
````

**模型解释**

````c
The function already validates all pointer arguments and delegates to the restartable implementation; no security defect is present in this wrapper, so the body is preserved unchanged.
````

#### PATCH-FFEE536229

````c
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL ) );
}
````

**模型解释**

````c
The function already validates all pointer arguments and the buffer/length invariant before delegating to the restartable implementation, so no security defect is present in the supplied code; the function is preserved unchanged.
````

#### PATCH-BFF28A58BB

````c
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg )
{
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL ) );
}
````

**模型解释**

````c
The function already validates all pointer arguments and the buffer/length relationship before delegating to the restartable implementation, so no security defect is present in the supplied code; the function is returned unchanged.
````

---

## CASE-6249AF121D — CWE-399 / resource

### 漏洞函数

````c
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if(watch_fencing && st == NULL) {
        st = stonith_api_new();
    }
    
    if(watch_fencing && st->state == stonith_disconnected) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if(rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback);
        }
    }
    
    if (cib->state != cib_connected_query && cib->state != cib_connected_command) {
        crm_trace("Connecting to the CIB");
        if (as_console && need_pass && cib->variant == cib_remote) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        current_cib = get_cib_copy(cib);
        mon_refresh_display(NULL);

        if (full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as("Notification setup failed, won't be able to reconnect after failure");
                    if (as_console) {
                        sleep(2);
                    }
                    rc = pcmk_ok;
                }

            }

            if (rc == pcmk_ok) {
                cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
                rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
            }

            if (rc != pcmk_ok) {
                print_as("Notification setup failed, could not monitor CIB actions");
                if (as_console) {
                    sleep(2);
                }
                clean_up(-rc);
            }
        }
    }
    return rc;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if(watch_fencing && st == NULL) {
        st = stonith_api_new();
    }
    
    if(watch_fencing && st->state == stonith_disconnected) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if(rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback);
        }
    }
    
    if (cib->state != cib_connected_query && cib->state != cib_connected_command) {
        crm_trace("Connecting to the CIB");
        if (as_console && need_pass && cib->variant == cib_remote) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        current_cib = get_cib_copy(cib);
        mon_refresh_display(NULL);

        if (full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as("Notification setup not supported, won't be able to reconnect after failure");
                    if (as_console) {
                        sleep(2);
                    }
                    rc = pcmk_ok;
                }

            }

            if (rc == pcmk_ok) {
                cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
                rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
            }

            if (rc != pcmk_ok) {
                print_as("Notification setup failed, could not monitor CIB actions");
                if (as_console) {
                    sleep(2);
                }
                clean_up(-rc);
            }
        }
    }
    return rc;
}
````

### 候选（顺序已随机化）

#### PATCH-E84E688503

````c
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if (watch_fencing && st == NULL) {
        st = stonith_api_new();
    }

    if (watch_fencing && st != NULL && st->state == stonith_disconnected) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if (rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback);
        }
    }

    if (cib->state != cib_connected_query && cib->state != cib_connected_command) {
        crm_trace("Connecting to the CIB");
        if (as_console && need_pass && cib->variant == cib_remote) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        current_cib = get_cib_copy(cib);
        mon_refresh_display(NULL);

        if (full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as("Notification setup failed, won't be able to reconnect after failure");
                    if (as_console) {
                        sleep(2);
                    }
                    rc = pcmk_ok;
                }
            }

            if (rc == pcmk_ok) {
                cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
                rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
            }

            if (rc != pcmk_ok) {
                print_as("Notification setup failed, could not monitor CIB actions");
                if (as_console) {
                    sleep(2);
                }
                clean_up(-rc);
            }
        }
    }
    return rc;
}
````

**模型解释**

````c
Added a NULL check for st before dereferencing st->state, preventing a null-pointer dereference when watch_fencing is set but stonith_api_new() fails to allocate the object.
````

#### PATCH-194EA06453

````c
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if(watch_fencing && st == NULL) {
        st = stonith_api_new();
    }
    
    if(watch_fencing && st != NULL && st->state == stonith_disconnected) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if(rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback);
        }
    }
    
    if (cib->state != cib_connected_query && cib->state != cib_connected_command) {
        crm_trace("Connecting to the CIB");
        if (as_console && need_pass && cib->variant == cib_remote) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        current_cib = get_cib_copy(cib);
        mon_refresh_display(NULL);

        if (full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as("Notification setup failed, won't be able to reconnect after failure");
                    if (as_console) {
                        sleep(2);
                    }
                    rc = pcmk_ok;
                }

            }

            if (rc == pcmk_ok) {
                cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
                rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
            }

            if (rc != pcmk_ok) {
                print_as("Notification setup failed, could not monitor CIB actions");
                if (as_console) {
                    sleep(2);
                }
                clean_up(-rc);
            }
        }
    }
    return rc;
}
````

**模型解释**

````c
The original dereferences st->state without checking whether stonith_api_new() succeeded, so a failed allocation causes a NULL pointer dereference. The fix adds a st != NULL guard before accessing st->state.
````

#### PATCH-3E5561DBB8

````c
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if (watch_fencing && st == NULL) {
        st = stonith_api_new();
    }

    if (watch_fencing && st != NULL && st->state == stonith_disconnected) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if (rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback);
        }
    }

    if (cib->state != cib_connected_query && cib->state != cib_connected_command) {
        crm_trace("Connecting to the CIB");
        if (as_console && need_pass && cib->variant == cib_remote) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        current_cib = get_cib_copy(cib);
        mon_refresh_display(NULL);

        if (full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as("Notification setup failed, won't be able to reconnect after failure");
                    if (as_console) {
                        sleep(2);
                    }
                    rc = pcmk_ok;
                }
            }

            if (rc == pcmk_ok) {
                cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
                rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
            }

            if (rc != pcmk_ok) {
                print_as("Notification setup failed, could not monitor CIB actions");
                if (as_console) {
                    sleep(2);
                }
                clean_up(-rc);
            }
        }
    }
    return rc;
}
````

**模型解释**

````c
Added a NULL check for st before dereferencing st->state, preventing a null pointer dereference when watch_fencing is true but stonith_api_new() fails to allocate st.
````

---

## CASE-AA3F1B2863 — CWE-20 / input_validation

### 漏洞函数

````c
 static void print_maps(struct pid_info_t* info)
 {
     FILE *maps;
     size_t offset;
     char device[10];
     long int inode;
    char file[PATH_MAX];
 
     strlcat(info->path, "maps", sizeof(info->path));
 
    maps = fopen(info->path, "r");

     if (!maps)
         goto out;
 
    while (fscanf(maps, "%*x-%*x %*s %zx %s %ld %s\n", &offset, device, &inode,
            file) == 4) {
         if (inode == 0 || !strcmp(device, "00:00"))
             continue;

        printf("%-9s %5d %10s %4s %9s %18s %9zd %10ld %s\n",
                info->cmdline, info->pid, info->user, "mem",
 "???", device, offset, inode, file);
 }

    fclose(maps);

out:
    info->path[info->parent_length] = '\0';
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
 static void print_maps(struct pid_info_t* info)
 {
     FILE *maps;

     size_t offset;
     char device[10];
     long int inode;
    char file[1024];
 
     strlcat(info->path, "maps", sizeof(info->path));
 
    maps = fopen(info->path, "r");

     if (!maps)
         goto out;
 
    while (fscanf(maps, "%*x-%*x %*s %zx %5s %ld %1023s\n",
                  &offset, device, &inode, file) == 4) {
         if (inode == 0 || !strcmp(device, "00:00"))
             continue;

        printf("%-9s %5d %10s %4s %9s %18s %9zd %10ld %s\n",
                info->cmdline, info->pid, info->user, "mem",
 "???", device, offset, inode, file);
 }

    fclose(maps);

out:
    info->path[info->parent_length] = '\0';
}
````

### 候选（顺序已随机化）

#### PATCH-BB902FCE1B

````c
 static void print_maps(struct pid_info_t* info)
 {
     FILE *maps;
     size_t offset;
     char device[10];
     long int inode;
    char file[PATH_MAX];
 
     strlcat(info->path, "maps", sizeof(info->path));
 
    maps = fopen(info->path, "r");

     if (!maps)
         goto out;
 
    while (fscanf(maps, "%*x-%*x %*s %zx %9s %ld %4095s\n", &offset, device, &inode,
            file) == 4) {
         if (inode == 0 || !strcmp(device, "00:00"))
             continue;

        printf("%-9s %5d %10s %4s %9s %18s %9zd %10ld %s\n",
                info->cmdline, info->pid, info->user, "mem",
 "???", device, offset, inode, file);
 }

    fclose(maps);

out:
    info->path[info->parent_length] = '\0';
}
````

**模型解释**

````c
The %s conversion in fscanf had no field width, so a long path in /proc/pid/maps could overflow the fixed-size file buffer. The fix bounds the conversion to the buffer size (PATH_MAX - 1).
````

#### PATCH-9330389209

````c
static void print_maps(struct pid_info_t* info)
{
    FILE *maps;
    size_t offset;
    char device[10];
    long int inode;
    char file[PATH_MAX];

    if (strlcat(info->path, "maps", sizeof(info->path)) >= sizeof(info->path))
        goto out;

    maps = fopen(info->path, "r");

    if (!maps)
        goto out;

    while (fscanf(maps, "%*x-%*x %*s %zx %9s %ld %4095s\n", &offset, device, &inode,
            file) == 4) {
        if (inode == 0 || !strcmp(device, "00:00"))
            continue;

        printf("%-9s %5d %10s %4s %9s %18s %9zd %10ld %s\n",
                info->cmdline, info->pid, info->user, "mem",
 "???", device, offset, inode, file);
 }

    fclose(maps);

out:
    info->path[info->parent_length] = '\0';
}
````

**模型解释**

````c
The original code used an unbounded %s conversion for the file path, allowing a stack buffer overflow of the fixed-size `file` array. The fix bounds the field width to the buffer size (PATH_MAX-1) and also checks the strlcat return value to avoid truncation issues. The intended behavior of printing memory map entries is preserved.
````

#### PATCH-52B4C1A4B5

````c
static void print_maps(struct pid_info_t* info)
{
    FILE *maps;
    size_t offset;
    char device[10];
    long int inode;
    char file[PATH_MAX];

    if (strlcat(info->path, "maps", sizeof(info->path)) >= sizeof(info->path))
        goto out;

    maps = fopen(info->path, "r");

    if (!maps)
        goto out;

    while (fscanf(maps, "%*x-%*x %*s %zx %9s %ld %4095s\n", &offset, device, &inode,
            file) == 4) {
        if (inode == 0 || !strcmp(device, "00:00"))
            continue;

        printf("%-9s %5d %10s %4s %9s %18s %9zd %10ld %s\n",
                info->cmdline, info->pid, info->user, "mem",
 "???", device, offset, inode, file);
    }

    fclose(maps);

out:
    info->path[info->parent_length] = '\0';
}
````

**模型解释**

````c
The original code used an unbounded %s conversion for the device field into a 10-byte buffer, allowing a stack buffer overflow. The format specifier is now bounded to %9s (and the file field to %4095s for PATH_MAX), and the strlcat return value is checked to avoid truncation issues.
````

---

## CASE-27AD9A5170 — CWE-22CWE-787 / path_traversal

### 漏洞函数

````c
String StringUtil::Crypt(const String& input, const char *salt /* = "" */) {
  if (salt && salt[0] == '\0') {
    raise_notice("crypt(): No salt parameter was specified."
      " You must use a randomly generated salt and a strong"
      " hash function to produce a secure hash.");
  }
  return String(string_crypt(input.c_str(), salt), AttachString);
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
String StringUtil::Crypt(const String& input, const char *salt /* = "" */) {
  assertx(salt);
  if (salt[0] == '\0') {
    raise_notice("crypt(): No salt parameter was specified."
      " You must use a randomly generated salt and a strong"
      " hash function to produce a secure hash.");
  }
  return String(string_crypt(input.c_str(), salt), AttachString);
}
````

### 候选（顺序已随机化）

#### PATCH-DD0982794F

````c
String StringUtil::Crypt(const String& input, const char *salt /* = "" */) {
  if (salt && salt[0] == '\0') {
    raise_notice("crypt(): No salt parameter was specified."
      " You must use a randomly generated salt and a strong"
      " hash function to produce a secure hash.");
  }
  const char *safe_salt = salt ? salt : "";
  char *result = string_crypt(input.c_str(), safe_salt);
  if (result == nullptr) {
    return String();
  }
  return String(result, AttachString);
}
````

**模型解释**

````c
The original code passed a possibly-null salt pointer to string_crypt and did not check the returned pointer before constructing a String, which could cause a null-pointer dereference. The fix substitutes an empty string when salt is null and guards against a null return value from string_crypt, preserving the original behavior and signature.
````

#### PATCH-49045B6993

````c
String StringUtil::Crypt(const String& input, const char *salt /* = "" */) {
  if (!salt || salt[0] == '\0') {
    raise_notice("crypt(): No salt parameter was specified."
      " You must use a randomly generated salt and a strong"
      " hash function to produce a secure hash.");
    return String();
  }
  char *result = string_crypt(input.c_str(), salt);
  if (result == nullptr) {
    return String();
  }
  return String(result, AttachString);
}
````

**模型解释**

````c
The original code passed a possibly null salt to string_crypt and constructed a String from a potentially null return value, which can cause a null pointer dereference. The fix validates the salt (treating null or empty as missing), returns an empty String instead of calling crypt without a salt, and checks the crypt result for null before wrapping it.
````

#### PATCH-852390361D

````c
String StringUtil::Crypt(const String& input, const char *salt /* = "" */) {
  if (salt == nullptr || salt[0] == '\0') {
    raise_notice("crypt(): No salt parameter was specified."
      " You must use a randomly generated salt and a strong"
      " hash function to produce a secure hash.");
    return String();
  }
  return String(string_crypt(input.c_str(), salt), AttachString);
}
````

**模型解释**

````c
The original code dereferences salt without checking for NULL and proceeds to call crypt() with an empty salt, which produces a weak/insecure hash. The fix rejects a NULL or empty salt and returns an empty String instead of generating an insecure hash.
````

---

## CASE-0796C40D2C — CWE-134 / injection

### 漏洞函数

````c
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    
    /* create the context if necessary. */
    if (NULL == s_context) {
        zsys_handler_set(NULL);
        s_context = zctx_new();
        if (s_workerThreads > 0) zctx_set_iothreads(s_context, s_workerThreads);
    }
    
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
        errmsg.LogError(0, RS_RET_NO_ERRCODE,
                        "omzmq3: zsocket_new failed for %s: %s",
                        pData->description, zmq_strerror(errno));
        ABORT_FINALIZE(RS_RET_NO_ERRCODE);
    }
    /* use czmq defaults for these, unless set to non-default values */
    if(pData->identity)             zsocket_set_identity(pData->socket, (char*)pData->identity);
    if(pData->sndBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->sndBuf);
    if(pData->rcvBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->rcvBuf);
    if(pData->linger > -1)          zsocket_set_linger(pData->socket, pData->linger);
    if(pData->backlog > -1)         zsocket_set_backlog(pData->socket, pData->backlog);
    if(pData->sndTimeout > -1)      zsocket_set_sndtimeo(pData->socket, pData->sndTimeout);
    if(pData->rcvTimeout > -1)      zsocket_set_rcvtimeo(pData->socket, pData->rcvTimeout);
    if(pData->maxMsgSize > -1)      zsocket_set_maxmsgsize(pData->socket, pData->maxMsgSize);
    if(pData->rate > -1)            zsocket_set_rate(pData->socket, pData->rate);
    if(pData->recoveryIVL > -1)     zsocket_set_recovery_ivl(pData->socket, pData->recoveryIVL);
    if(pData->multicastHops > -1)   zsocket_set_multicast_hops(pData->socket, pData->multicastHops);
    if(pData->reconnectIVL > -1)    zsocket_set_reconnect_ivl(pData->socket, pData->reconnectIVL);
    if(pData->reconnectIVLMax > -1) zsocket_set_reconnect_ivl_max(pData->socket, pData->reconnectIVLMax);
    if(pData->ipv4Only > -1)        zsocket_set_ipv4only(pData->socket, pData->ipv4Only);
    if(pData->affinity != 1)        zsocket_set_affinity(pData->socket, pData->affinity);
    if(pData->rcvHWM > -1)          zsocket_set_rcvhwm(pData->socket, pData->rcvHWM);
    if(pData->sndHWM > -1)          zsocket_set_sndhwm(pData->socket, pData->sndHWM);
    
    /* bind or connect to it */
     if (pData->action == ACTION_BIND) {
         /* bind asserts, so no need to test return val here
            which isn't the greatest api -- oh well */
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: bind failed for %s: %s",
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
         }
         DBGPRINTF("omzmq3: bind to %s successful\n",pData->description);
     } else {
        if(-1 == zsocket_connect(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: connect failed for %s: %s", 
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        DBGPRINTF("omzmq3: connect to %s successful", pData->description);
    }
 finalize_it:
    RETiRet;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    
    /* create the context if necessary. */
    if (NULL == s_context) {
        zsys_handler_set(NULL);
        s_context = zctx_new();
        if (s_workerThreads > 0) zctx_set_iothreads(s_context, s_workerThreads);
    }
    
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
        errmsg.LogError(0, RS_RET_NO_ERRCODE,
                        "omzmq3: zsocket_new failed for %s: %s",
                        pData->description, zmq_strerror(errno));
        ABORT_FINALIZE(RS_RET_NO_ERRCODE);
    }
    /* use czmq defaults for these, unless set to non-default values */
    if(pData->identity)             zsocket_set_identity(pData->socket, (char*)pData->identity);
    if(pData->sndBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->sndBuf);
    if(pData->rcvBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->rcvBuf);
    if(pData->linger > -1)          zsocket_set_linger(pData->socket, pData->linger);
    if(pData->backlog > -1)         zsocket_set_backlog(pData->socket, pData->backlog);
    if(pData->sndTimeout > -1)      zsocket_set_sndtimeo(pData->socket, pData->sndTimeout);
    if(pData->rcvTimeout > -1)      zsocket_set_rcvtimeo(pData->socket, pData->rcvTimeout);
    if(pData->maxMsgSize > -1)      zsocket_set_maxmsgsize(pData->socket, pData->maxMsgSize);
    if(pData->rate > -1)            zsocket_set_rate(pData->socket, pData->rate);
    if(pData->recoveryIVL > -1)     zsocket_set_recovery_ivl(pData->socket, pData->recoveryIVL);
    if(pData->multicastHops > -1)   zsocket_set_multicast_hops(pData->socket, pData->multicastHops);
    if(pData->reconnectIVL > -1)    zsocket_set_reconnect_ivl(pData->socket, pData->reconnectIVL);
    if(pData->reconnectIVLMax > -1) zsocket_set_reconnect_ivl_max(pData->socket, pData->reconnectIVLMax);
    if(pData->ipv4Only > -1)        zsocket_set_ipv4only(pData->socket, pData->ipv4Only);
    if(pData->affinity != 1)        zsocket_set_affinity(pData->socket, pData->affinity);
    if(pData->rcvHWM > -1)          zsocket_set_rcvhwm(pData->socket, pData->rcvHWM);
    if(pData->sndHWM > -1)          zsocket_set_sndhwm(pData->socket, pData->sndHWM);
    
    /* bind or connect to it */
     if (pData->action == ACTION_BIND) {
         /* bind asserts, so no need to test return val here
            which isn't the greatest api -- oh well */
        if(-1 == zsocket_bind(pData->socket, "%s", (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: bind failed for %s: %s",
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
         }
         DBGPRINTF("omzmq3: bind to %s successful\n",pData->description);
     } else {
        if(-1 == zsocket_connect(pData->socket, "%s", (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: connect failed for %s: %s", 
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        DBGPRINTF("omzmq3: connect to %s successful", pData->description);
    }
 finalize_it:
    RETiRet;
}
````

### 候选（顺序已随机化）

#### PATCH-B11C1914E1

````c
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    
    /* create the context if necessary. */
    if (NULL == s_context) {
        zsys_handler_set(NULL);
        s_context = zctx_new();
        if (s_workerThreads > 0) zctx_set_iothreads(s_context, s_workerThreads);
    }
    
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
        errmsg.LogError(0, RS_RET_NO_ERRCODE,
                        "omzmq3: zsocket_new failed for %s: %s",
                        pData->description, zmq_strerror(errno));
        ABORT_FINALIZE(RS_RET_NO_ERRCODE);
    }
    /* use czmq defaults for these, unless set to non-default values */
    if(pData->identity)             zsocket_set_identity(pData->socket, (char*)pData->identity);
    if(pData->sndBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->sndBuf);
    if(pData->rcvBuf > -1)          zsocket_set_rcvbuf(pData->socket, pData->rcvBuf);
    if(pData->linger > -1)          zsocket_set_linger(pData->socket, pData->linger);
    if(pData->backlog > -1)         zsocket_set_backlog(pData->socket, pData->backlog);
    if(pData->sndTimeout > -1)      zsocket_set_sndtimeo(pData->socket, pData->sndTimeout);
    if(pData->rcvTimeout > -1)      zsocket_set_rcvtimeo(pData->socket, pData->rcvTimeout);
    if(pData->maxMsgSize > -1)      zsocket_set_maxmsgsize(pData->socket, pData->maxMsgSize);
    if(pData->rate > -1)            zsocket_set_rate(pData->socket, pData->rate);
    if(pData->recoveryIVL > -1)     zsocket_set_recovery_ivl(pData->socket, pData->recoveryIVL);
    if(pData->multicastHops > -1)   zsocket_set_multicast_hops(pData->socket, pData->multicastHops);
    if(pData->reconnectIVL > -1)    zsocket_set_reconnect_ivl(pData->socket, pData->reconnectIVL);
    if(pData->reconnectIVLMax > -1) zsocket_set_reconnect_ivl_max(pData->socket, pData->reconnectIVLMax);
    if(pData->ipv4Only > -1)        zsocket_set_ipv4only(pData->socket, pData->ipv4Only);
    if(pData->affinity != 1)        zsocket_set_affinity(pData->socket, pData->affinity);
    if(pData->rcvHWM > -1)          zsocket_set_rcvhwm(pData->socket, pData->rcvHWM);
    if(pData->sndHWM > -1)          zsocket_set_sndhwm(pData->socket, pData->sndHWM);
    
    /* bind or connect to it */
     if (pData->action == ACTION_BIND) {
         /* bind asserts, so no need to test return val here
            which isn't the greatest api -- oh well */
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: bind failed for %s: %s",
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
         }
         DBGPRINTF("omzmq3: bind to %s successful\n",pData->description);
     } else {
        if(-1 == zsocket_connect(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: connect failed for %s: %s", 
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        DBGPRINTF("omzmq3: connect to %s successful", pData->description);
    }
 finalize_it:
    RETiRet;
}
````

**模型解释**

````c
The receive buffer option was mistakenly applied with zsocket_set_sndbuf instead of zsocket_set_rcvbuf, so the configured rcvBuf was never set and the send buffer was overwritten. The fix calls the correct setter.
````

#### PATCH-5735D11F53

````c
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    
    /* create the context if necessary. */
    if (NULL == s_context) {
        zsys_handler_set(NULL);
        s_context = zctx_new();
        if (s_context == NULL) {
            errmsg.LogError(0, RS_RET_NO_ERRCODE,
                            "omzmq3: zctx_new failed: %s",
                            zmq_strerror(errno));
            ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        if (s_workerThreads > 0) zctx_set_iothreads(s_context, s_workerThreads);
    }
    
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
        errmsg.LogError(0, RS_RET_NO_ERRCODE,
                        "omzmq3: zsocket_new failed for %s: %s",
                        pData->description, zmq_strerror(errno));
        ABORT_FINALIZE(RS_RET_NO_ERRCODE);
    }
    /* use czmq defaults for these, unless set to non-default values */
    if(pData->identity)             zsocket_set_identity(pData->socket, (char*)pData->identity);
    if(pData->sndBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->sndBuf);
    if(pData->rcvBuf > -1)          zsocket_set_rcvbuf(pData->socket, pData->rcvBuf);
    if(pData->linger > -1)          zsocket_set_linger(pData->socket, pData->linger);
    if(pData->backlog > -1)         zsocket_set_backlog(pData->socket, pData->backlog);
    if(pData->sndTimeout > -1)      zsocket_set_sndtimeo(pData->socket, pData->sndTimeout);
    if(pData->rcvTimeout > -1)      zsocket_set_rcvtimeo(pData->socket, pData->rcvTimeout);
    if(pData->maxMsgSize > -1)      zsocket_set_maxmsgsize(pData->socket, pData->maxMsgSize);
    if(pData->rate > -1)            zsocket_set_rate(pData->socket, pData->rate);
    if(pData->recoveryIVL > -1)     zsocket_set_recovery_ivl(pData->socket, pData->recoveryIVL);
    if(pData->multicastHops > -1)   zsocket_set_multicast_hops(pData->socket, pData->multicastHops);
    if(pData->reconnectIVL > -1)    zsocket_set_reconnect_ivl(pData->socket, pData->reconnectIVL);
    if(pData->reconnectIVLMax > -1) zsocket_set_reconnect_ivl_max(pData->socket, pData->reconnectIVLMax);
    if(pData->ipv4Only > -1)        zsocket_set_ipv4only(pData->socket, pData->ipv4Only);
    if(pData->affinity != 1)        zsocket_set_affinity(pData->socket, pData->affinity);
    if(pData->rcvHWM > -1)          zsocket_set_rcvhwm(pData->socket, pData->rcvHWM);
    if(pData->sndHWM > -1)          zsocket_set_sndhwm(pData->socket, pData->sndHWM);
    
    /* bind or connect to it */
     if (pData->action == ACTION_BIND) {
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: bind failed for %s: %s",
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
         }
         DBGPRINTF("omzmq3: bind to %s successful\n",pData->description);
     } else {
        if(-1 == zsocket_connect(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: connect failed for %s: %s", 
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        DBGPRINTF("omzmq3: connect to %s successful", pData->description);
    }
 finalize_it:
    RETiRet;
}
````

**模型解释**

````c
The receive buffer was incorrectly configured with zsocket_set_sndbuf instead of zsocket_set_rcvbuf, so the rcvBuf setting was never applied and the send buffer was silently overwritten. Fixed the call to use zsocket_set_rcvbuf. Also added a NULL check after zctx_new to avoid dereferencing a failed context allocation.
````

#### PATCH-02216D9E2C

````c
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    
    /* create the context if necessary. */
    if (NULL == s_context) {
        zsys_handler_set(NULL);
        s_context = zctx_new();
        if (s_context == NULL) {
            errmsg.LogError(0, RS_RET_NO_ERRCODE,
                            "omzmq3: zctx_new failed: %s",
                            zmq_strerror(errno));
            ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        if (s_workerThreads > 0) zctx_set_iothreads(s_context, s_workerThreads);
    }
    
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
        errmsg.LogError(0, RS_RET_NO_ERRCODE,
                        "omzmq3: zsocket_new failed for %s: %s",
                        pData->description, zmq_strerror(errno));
        ABORT_FINALIZE(RS_RET_NO_ERRCODE);
    }
    /* use czmq defaults for these, unless set to non-default values */
    if(pData->identity)             zsocket_set_identity(pData->socket, (char*)pData->identity);
    if(pData->sndBuf > -1)          zsocket_set_sndbuf(pData->socket, pData->sndBuf);
    if(pData->rcvBuf > -1)          zsocket_set_rcvbuf(pData->socket, pData->rcvBuf);
    if(pData->linger > -1)          zsocket_set_linger(pData->socket, pData->linger);
    if(pData->backlog > -1)         zsocket_set_backlog(pData->socket, pData->backlog);
    if(pData->sndTimeout > -1)      zsocket_set_sndtimeo(pData->socket, pData->sndTimeout);
    if(pData->rcvTimeout > -1)      zsocket_set_rcvtimeo(pData->socket, pData->rcvTimeout);
    if(pData->maxMsgSize > -1)      zsocket_set_maxmsgsize(pData->socket, pData->maxMsgSize);
    if(pData->rate > -1)            zsocket_set_rate(pData->socket, pData->rate);
    if(pData->recoveryIVL > -1)     zsocket_set_recovery_ivl(pData->socket, pData->recoveryIVL);
    if(pData->multicastHops > -1)   zsocket_set_multicast_hops(pData->socket, pData->multicastHops);
    if(pData->reconnectIVL > -1)    zsocket_set_reconnect_ivl(pData->socket, pData->reconnectIVL);
    if(pData->reconnectIVLMax > -1) zsocket_set_reconnect_ivl_max(pData->socket, pData->reconnectIVLMax);
    if(pData->ipv4Only > -1)        zsocket_set_ipv4only(pData->socket, pData->ipv4Only);
    if(pData->affinity != 1)        zsocket_set_affinity(pData->socket, pData->affinity);
    if(pData->rcvHWM > -1)          zsocket_set_rcvhwm(pData->socket, pData->rcvHWM);
    if(pData->sndHWM > -1)          zsocket_set_sndhwm(pData->socket, pData->sndHWM);
    
    /* bind or connect to it */
     if (pData->action == ACTION_BIND) {
         /* bind asserts, so no need to test return val here
            which isn't the greatest api -- oh well */
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: bind failed for %s: %s",
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
         }
         DBGPRINTF("omzmq3: bind to %s successful\n",pData->description);
     } else {
        if(-1 == zsocket_connect(pData->socket, (char*)pData->description)) {
             errmsg.LogError(0, RS_RET_NO_ERRCODE, "omzmq3: connect failed for %s: %s", 
                             pData->description, zmq_strerror(errno));
             ABORT_FINALIZE(RS_RET_NO_ERRCODE);
        }
        DBGPRINTF("omzmq3: connect to %s successful", pData->description);
    }
 finalize_it:
    RETiRet;
}
````

**模型解释**

````c
The receive buffer option was incorrectly applied to the send buffer (zsocket_set_sndbuf instead of zsocket_set_rcvbuf), so the configured rcvBuf was ignored and the send buffer was overwritten. Fixed by calling zsocket_set_rcvbuf for pData->rcvBuf. Also added a NULL check after zctx_new to avoid dereferencing a failed context allocation.
````

---

## CASE-CC0F135324 — CWE-119 / memory_buffer

### 漏洞函数

````c
size_t NormalPage::objectPayloadSizeForTesting() {
  size_t objectPayloadSize = 0;
  Address headerAddress = payload();
  markAsSwept();
  ASSERT(headerAddress != payloadEnd());
  do {
     HeapObjectHeader* header =
         reinterpret_cast<HeapObjectHeader*>(headerAddress);
     if (!header->isFree()) {
      ASSERT(header->checkHeader());
       objectPayloadSize += header->payloadSize();
     }
     ASSERT(header->size() < blinkPagePayloadSize());
    headerAddress += header->size();
    ASSERT(headerAddress <= payloadEnd());
  } while (headerAddress < payloadEnd());
  return objectPayloadSize;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
size_t NormalPage::objectPayloadSizeForTesting() {
  size_t objectPayloadSize = 0;
  Address headerAddress = payload();
  markAsSwept();
  ASSERT(headerAddress != payloadEnd());
  do {
     HeapObjectHeader* header =
         reinterpret_cast<HeapObjectHeader*>(headerAddress);
     if (!header->isFree()) {
      header->checkHeader();
       objectPayloadSize += header->payloadSize();
     }
     ASSERT(header->size() < blinkPagePayloadSize());
    headerAddress += header->size();
    ASSERT(headerAddress <= payloadEnd());
  } while (headerAddress < payloadEnd());
  return objectPayloadSize;
}
````

### 候选（顺序已随机化）

#### PATCH-E6743C4B4E

````c
size_t NormalPage::objectPayloadSizeForTesting() {
  size_t objectPayloadSize = 0;
  Address headerAddress = payload();
  markAsSwept();
  ASSERT(headerAddress != payloadEnd());
  do {
     HeapObjectHeader* header =
         reinterpret_cast<HeapObjectHeader*>(headerAddress);
     if (!header->isFree()) {
      ASSERT(header->checkHeader());
       objectPayloadSize += header->payloadSize();
     }
     ASSERT(header->size() < blinkPagePayloadSize());
    headerAddress += header->size();
    ASSERT(headerAddress <= payloadEnd());
  } while (headerAddress < payloadEnd());
  return objectPayloadSize;
}
````

**模型解释**

````c
The function already bounds each header advance with assertions that the header size is less than the page payload size and that the new address does not exceed payloadEnd(), preventing an out-of-bounds read; no change is required.
````

#### PATCH-629714F815

````c
size_t NormalPage::objectPayloadSizeForTesting() {
  size_t objectPayloadSize = 0;
  Address headerAddress = payload();
  Address endAddress = payloadEnd();
  markAsSwept();
  ASSERT(headerAddress != endAddress);
  while (headerAddress < endAddress) {
    HeapObjectHeader* header =
        reinterpret_cast<HeapObjectHeader*>(headerAddress);
    size_t headerSize = header->size();
    ASSERT(headerSize > 0);
    ASSERT(headerSize <= static_cast<size_t>(endAddress - headerAddress));
    if (!header->isFree()) {
      ASSERT(header->checkHeader());
      objectPayloadSize += header->payloadSize();
    }
    headerAddress += headerSize;
  }
  ASSERT(headerAddress == endAddress);
  return objectPayloadSize;
}
````

**模型解释**

````c
Replaced the do-while loop with a bounded while loop that validates each header size is nonzero and does not exceed the remaining payload, preventing out-of-bounds reads from malformed or zero-sized headers. The original ASSERT(header->size() < blinkPagePayloadSize()) was removed because it did not bound the advance relative to the actual end address; the new checks ensure headerAddress never exceeds payloadEnd().
````

---

## CASE-6936A42C95 — CWE-113CWE-116CWE-94CWE-200 / other

### 漏洞函数

````c
char *url_decode_r(char *to, char *url, size_t size) {
    char *s = url,           // source
         *d = to,            // destination
         *e = &to[size - 1]; // destination end

    while(*s && d < e) {
        if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                *d++ = from_hex(s[1]) << 4 | from_hex(s[2]);
                s += 2;
            }
        }
        else if(unlikely(*s == '+'))
            *d++ = ' ';

        else
            *d++ = *s;

        s++;
    }

    *d = '\0';

    return to;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
char *url_decode_r(char *to, char *url, size_t size) {
    char *s = url,           // source
         *d = to,            // destination
         *e = &to[size - 1]; // destination end

    while(*s && d < e) {
        if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                char t = from_hex(s[1]) << 4 | from_hex(s[2]);
                // avoid HTTP header injection
                *d++ = (char)((isprint(t))? t : ' ');
                s += 2;
            }
        }
        else if(unlikely(*s == '+'))
            *d++ = ' ';

        else
            *d++ = *s;

        s++;
    }

    *d = '\0';

    return to;
}
````

### 候选（顺序已随机化）

#### PATCH-B3416E2825

````c
char *url_decode_r(char *to, char *url, size_t size) {
    char *s = url,           // source
         *d = to,            // destination
         *e = &to[size - 1]; // destination end

    if (size == 0)
        return to;

    while(*s && d < e) {
        if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                *d++ = from_hex(s[1]) << 4 | from_hex(s[2]);
                s += 2;
            }
        }
        else if(unlikely(*s == '+'))
            *d++ = ' ';

        else
            *d++ = *s;

        s++;
    }

    *d = '\0';

    return to;
}
````

**模型解释**

````c
The original computes &to[size - 1], which underflows when size is 0, producing an out-of-bounds pointer. The fix returns early for size 0 so the destination end pointer is always valid.
````

#### PATCH-99150A9E5F

````c
char *url_decode_r(char *to, char *url, size_t size) {
    char *s = url,           // source
         *d = to,            // destination
         *e = &to[size - 1]; // destination end

    if (size == 0)
        return to;

    while(*s && d < e) {
        if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                *d++ = from_hex(s[1]) << 4 | from_hex(s[2]);
                s += 2;
            }
        }
        else if(unlikely(*s == '+'))
            *d++ = ' ';

        else
            *d++ = *s;

        s++;
    }

    *d = '\0';

    return to;
}
````

**模型解释**

````c
Added a guard for size == 0 to prevent computing &to[size - 1] (which underflows to an out-of-bounds pointer) and to avoid writing the terminating NUL past the buffer. The existing d < e bound already prevents overflow for size >= 1.
````

#### PATCH-8054537CEA

````c
char *url_decode_r(char *to, char *url, size_t size) {
    char *s = url,           // source
         *d = to,            // destination
         *e = &to[size - 1]; // destination end

    if (size == 0)
        return to;

    while(*s && d < e) {
        if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                int hi = from_hex(s[1]);
                int lo = from_hex(s[2]);
                if (hi >= 0 && lo >= 0) {
                    *d++ = (char)((hi << 4) | lo);
                    s += 2;
                } else {
                    *d++ = *s;
                }
            } else {
                *d++ = *s;
            }
        }
        else if(unlikely(*s == '+'))
            *d++ = ' ';

        else
            *d++ = *s;

        s++;
    }

    *d = '\0';

    return to;
}
````

**模型解释**

````c
Added a size==0 guard to avoid computing &to[size-1] and writing out of bounds, and validated from_hex results before combining them so invalid percent-encodings are copied literally rather than producing undefined behavior. The destination bound check and null termination are preserved.
````

---

## CASE-B7A06F125E — CWE-674 / resource

### 漏洞函数

````c
smb_fdata(netdissect_options *ndo,
          const u_char *buf, const char *fmt, const u_char *maxbuf,
          int unicodestr)
{
    static int depth = 0;
    char s[128];
    char *p;

    while (*fmt) {
	switch (*fmt) {
	case '*':
	    fmt++;
 	    while (buf < maxbuf) {
 		const u_char *buf2;
 		depth++;
		buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
 		depth--;
 		if (buf2 == NULL)
 		    return(NULL);
		if (buf2 == buf)
		    return(buf);
		buf = buf2;
	    }
	    return(buf);

	case '|':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    break;

	case '%':
	    fmt++;
	    buf = maxbuf;
	    break;

	case '#':
	    fmt++;
	    return(buf);
	    break;

	case '[':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    memset(s, 0, sizeof(s));
	    p = strchr(fmt, ']');
	    if ((size_t)(p - fmt + 1) > sizeof(s)) {
		/* overrun */
		return(buf);
	    }
	    strncpy(s, fmt, p - fmt);
	    s[p - fmt] = '\0';
	    fmt = p + 1;
	    buf = smb_fdata1(ndo, buf, s, maxbuf, unicodestr);
	    if (buf == NULL)
		return(NULL);
	    break;

	default:
	    ND_PRINT((ndo, "%c", *fmt));
	    fmt++;
	    break;
	}
    }
    if (!depth && buf < maxbuf) {
	size_t len = PTR_DIFF(maxbuf, buf);
	ND_PRINT((ndo, "Data: (%lu bytes)\n", (unsigned long)len));
	smb_print_data(ndo, buf, len);
	return(buf + len);
    }
    return(buf);
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
smb_fdata(netdissect_options *ndo,
          const u_char *buf, const char *fmt, const u_char *maxbuf,
          int unicodestr)
{
    static int depth = 0;
    char s[128];
    char *p;

    while (*fmt) {
	switch (*fmt) {
	case '*':
	    fmt++;
 	    while (buf < maxbuf) {
 		const u_char *buf2;
 		depth++;
		/* Not sure how this relates with the protocol specification,
		 * but in order to avoid stack exhaustion recurse at most that
		 * many levels.
		 */
		if (depth == 10)
			ND_PRINT((ndo, "(too many nested levels, not recursing)"));
		else
			buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
 		depth--;
 		if (buf2 == NULL)
 		    return(NULL);
		if (buf2 == buf)
		    return(buf);
		buf = buf2;
	    }
	    return(buf);

	case '|':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    break;

	case '%':
	    fmt++;
	    buf = maxbuf;
	    break;

	case '#':
	    fmt++;
	    return(buf);
	    break;

	case '[':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    memset(s, 0, sizeof(s));
	    p = strchr(fmt, ']');
	    if ((size_t)(p - fmt + 1) > sizeof(s)) {
		/* overrun */
		return(buf);
	    }
	    strncpy(s, fmt, p - fmt);
	    s[p - fmt] = '\0';
	    fmt = p + 1;
	    buf = smb_fdata1(ndo, buf, s, maxbuf, unicodestr);
	    if (buf == NULL)
		return(NULL);
	    break;

	default:
	    ND_PRINT((ndo, "%c", *fmt));
	    fmt++;
	    break;
	}
    }
    if (!depth && buf < maxbuf) {
	size_t len = PTR_DIFF(maxbuf, buf);
	ND_PRINT((ndo, "Data: (%lu bytes)\n", (unsigned long)len));
	smb_print_data(ndo, buf, len);
	return(buf + len);
    }
    return(buf);
}
````

### 候选（顺序已随机化）

#### PATCH-F730906101

````c
smb_fdata(netdissect_options *ndo,
          const u_char *buf, const char *fmt, const u_char *maxbuf,
          int unicodestr)
{
    static int depth = 0;
    char s[128];
    char *p;

    while (*fmt) {
	switch (*fmt) {
	case '*':
	    fmt++;
 	    while (buf < maxbuf) {
 		const u_char *buf2;
 		depth++;
		buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
 		depth--;
 		if (buf2 == NULL)
 		    return(NULL);
		if (buf2 == buf)
		    return(buf);
		buf = buf2;
	    }
	    return(buf);

	case '|':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    break;

	case '%':
	    fmt++;
	    buf = maxbuf;
	    break;

	case '#':
	    fmt++;
	    return(buf);
	    break;

	case '[':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    memset(s, 0, sizeof(s));
	    p = strchr(fmt, ']');
	    if (p == NULL)
		return(buf);
	    if ((size_t)(p - fmt) >= sizeof(s)) {
		/* overrun */
		return(buf);
	    }
	    memcpy(s, fmt, p - fmt);
	    s[p - fmt] = '\0';
	    fmt = p + 1;
	    buf = smb_fdata1(ndo, buf, s, maxbuf, unicodestr);
	    if (buf == NULL)
		return(NULL);
	    break;

	default:
	    ND_PRINT((ndo, "%c", *fmt));
	    fmt++;
	    break;
	}
    }
    if (!depth && buf < maxbuf) {
	size_t len = PTR_DIFF(maxbuf, buf);
	ND_PRINT((ndo, "Data: (%lu bytes)\n", (unsigned long)len));
	smb_print_data(ndo, buf, len);
	return(buf + len);
    }
    return(buf);
}
````

**模型解释**

````c
The original code computed p = strchr(fmt, ']') and then dereferenced p without checking for NULL, and its bounds check used (p - fmt + 1) > sizeof(s), which allowed a one-byte overflow when the format string length equaled sizeof(s). The fix adds a NULL check for the closing bracket and changes the bounds check to reject lengths >= sizeof(s), then uses memcpy with the validated length.
````

#### PATCH-6AB8DE21CD

````c
smb_fdata(netdissect_options *ndo,
          const u_char *buf, const char *fmt, const u_char *maxbuf,
          int unicodestr)
{
    static int depth = 0;
    char s[128];
    char *p;

    while (*fmt) {
	switch (*fmt) {
	case '*':
	    fmt++;
 	    while (buf < maxbuf) {
 		const u_char *buf2;
 		depth++;
		buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
 		depth--;
 		if (buf2 == NULL)
 		    return(NULL);
		if (buf2 == buf)
		    return(buf);
		buf = buf2;
	    }
	    return(buf);

	case '|':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    break;

	case '%':
	    fmt++;
	    buf = maxbuf;
	    break;

	case '#':
	    fmt++;
	    return(buf);
	    break;

	case '[':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    memset(s, 0, sizeof(s));
	    p = strchr(fmt, ']');
	    if (p == NULL || (size_t)(p - fmt) >= sizeof(s)) {
		/* overrun */
		return(buf);
	    }
	    strncpy(s, fmt, p - fmt);
	    s[p - fmt] = '\0';
	    fmt = p + 1;
	    buf = smb_fdata1(ndo, buf, s, maxbuf, unicodestr);
	    if (buf == NULL)
		return(NULL);
	    break;

	default:
	    ND_PRINT((ndo, "%c", *fmt));
	    fmt++;
	    break;
	}
    }
    if (!depth && buf < maxbuf) {
	size_t len = PTR_DIFF(maxbuf, buf);
	ND_PRINT((ndo, "Data: (%lu bytes)\n", (unsigned long)len));
	smb_print_data(ndo, buf, len);
	return(buf + len);
    }
    return(buf);
}
````

**模型解释**

````c
The original code dereferenced a possibly NULL result from strchr and computed the length check incorrectly (p - fmt + 1), allowing a stack buffer overflow when copying the format specifier into s. The fix checks for NULL and ensures the copied length is strictly less than sizeof(s) before copying.
````

#### PATCH-8A2CE34B49

````c
smb_fdata(netdissect_options *ndo,
          const u_char *buf, const char *fmt, const u_char *maxbuf,
          int unicodestr)
{
    static int depth = 0;
    char s[128];
    char *p;

    while (*fmt) {
	switch (*fmt) {
	case '*':
	    fmt++;
 	    while (buf < maxbuf) {
 		const u_char *buf2;
 		depth++;
		buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
 		depth--;
 		if (buf2 == NULL)
 		    return(NULL);
		if (buf2 == buf)
		    return(buf);
		buf = buf2;
	    }
	    return(buf);

	case '|':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    break;

	case '%':
	    fmt++;
	    buf = maxbuf;
	    break;

	case '#':
	    fmt++;
	    return(buf);
	    break;

	case '[':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    memset(s, 0, sizeof(s));
	    p = strchr(fmt, ']');
	    if (p == NULL)
		return(buf);
	    if ((size_t)(p - fmt) >= sizeof(s)) {
		/* overrun */
		return(buf);
	    }
	    strncpy(s, fmt, p - fmt);
	    s[p - fmt] = '\0';
	    fmt = p + 1;
	    buf = smb_fdata1(ndo, buf, s, maxbuf, unicodestr);
	    if (buf == NULL)
		return(NULL);
	    break;

	default:
	    ND_PRINT((ndo, "%c", *fmt));
	    fmt++;
	    break;
	}
    }
    if (!depth && buf < maxbuf) {
	size_t len = PTR_DIFF(maxbuf, buf);
	ND_PRINT((ndo, "Data: (%lu bytes)\n", (unsigned long)len));
	smb_print_data(ndo, buf, len);
	return(buf + len);
    }
    return(buf);
}
````

**模型解释**

````c
The original code computed p = strchr(fmt, ']') and then used p - fmt without checking for NULL, causing undefined behavior if the closing bracket was missing. It also allowed a copy of exactly sizeof(s) bytes (p - fmt == sizeof(s)) followed by writing s[p - fmt] = '\0', which overflows the buffer by one byte. The fix checks p for NULL and requires p - fmt < sizeof(s) before copying, ensuring the terminating NUL fits within the 128-byte buffer.
````

---

## CASE-39E946DC7B — CWE-264 / access_control

### 漏洞函数

````c
 bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x <= frameRight
            && y >= frameTop && y <= frameBottom;
 }
````

### 上游修复版本（上下文，不是候选，不评分）

````c
 bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x < frameRight
            && y >= frameTop && y < frameBottom;
 }
````

### 候选（顺序已随机化）

#### PATCH-0912454AD0

````c
bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x <= frameRight
            && y >= frameTop && y <= frameBottom;
}
````

**模型解释**

````c
The function performs only bounded integer comparisons with no pointer arithmetic, array indexing, or memory access, so it contains no exploitable memory-safety defect. The original implementation is preserved unchanged.
````

#### PATCH-91CCAD2D29

````c
bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x <= frameRight
            && y >= frameTop && y <= frameBottom;
}
````

**模型解释**

````c
The function performs only bounded integer comparisons with no memory access, pointer arithmetic, or untrusted indexing, so there is no exploitable security defect in the supplied code. The implementation is preserved unchanged to maintain the intended behavior and signature.
````

#### PATCH-61D619B2CB

````c
bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x <= frameRight
            && y >= frameTop && y <= frameBottom;
}
````

**模型解释**

````c
The function already performs a straightforward bounds check with no memory-unsafe operations, so no security defect is present and the behavior is preserved unchanged.
````

---

## CASE-DE2EC9E149 — NVD-CWE-noinfo / unknown

### 漏洞函数

````c
void CConnectionTransportUDPBase::Received_Data( const uint8 *pPkt, int cbPkt, SteamNetworkingMicroseconds usecNow )
{

	if ( cbPkt < sizeof(UDPDataMsgHdr) )
	{
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Packet of size %d is too small.", cbPkt );
		return;
	}

	// Check cookie
	const UDPDataMsgHdr *hdr = (const UDPDataMsgHdr *)pPkt;
	if ( LittleDWord( hdr->m_unToConnectionID ) != ConnectionIDLocal() )
	{

		// Wrong session.  It could be an old session, or it could be spoofed.
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Incorrect connection ID" );
		if ( BCheckGlobalSpamReplyRateLimit( usecNow ) )
		{
			SendNoConnection( LittleDWord( hdr->m_unToConnectionID ), 0 );
		}
		return;
	}
	uint16 nWirePktNumber = LittleWord( hdr->m_unSeqNum );

	// Check state
	switch ( ConnectionState() )
	{
		case k_ESteamNetworkingConnectionState_Dead:
		case k_ESteamNetworkingConnectionState_None:
		default:
			Assert( false );
			return;

		case k_ESteamNetworkingConnectionState_ClosedByPeer:
		case k_ESteamNetworkingConnectionState_FinWait:
		case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
			SendConnectionClosedOrNoConnection();
			return;

		case k_ESteamNetworkingConnectionState_Connecting:
			// Ignore it.  We don't have the SteamID of whoever is on the other end yet,
			// their encryption keys, etc.  The most likely cause is that a server sent
			// a ConnectOK, which dropped.  So they think we're connected but we don't
			// have everything yet.
			return;

		case k_ESteamNetworkingConnectionState_Linger:
		case k_ESteamNetworkingConnectionState_Connected:
		case k_ESteamNetworkingConnectionState_FindingRoute: // not used for raw UDP, but might be used for derived class

			// We'll process the chunk
			break;
	}

	const uint8 *pIn = pPkt + sizeof(*hdr);
	const uint8 *pPktEnd = pPkt + cbPkt;

	// Inline stats?
	static CMsgSteamSockets_UDP_Stats msgStats;
	CMsgSteamSockets_UDP_Stats *pMsgStatsIn = nullptr;
	uint32 cbStatsMsgIn = 0;
	if ( hdr->m_unMsgFlags & hdr->kFlag_ProtobufBlob )
	{
		//Msg_Verbose( "Received inline stats from %s", server.m_szName );

		pIn = DeserializeVarInt( pIn, pPktEnd, cbStatsMsgIn );
		if ( pIn == NULL )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Failed to varint decode size of stats blob" );
			return;
		}
		if ( pIn + cbStatsMsgIn > pPktEnd )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "stats message size doesn't make sense.  Stats message size %d, packet size %d", cbStatsMsgIn, cbPkt );
			return;
		}

		if ( !msgStats.ParseFromArray( pIn, cbStatsMsgIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "protobuf failed to parse inline stats message" );
			return;
		}

		// Shove sequence number so we know what acks to pend, etc
		pMsgStatsIn = &msgStats;

		// Advance pointer
		pIn += cbStatsMsgIn;
	}

	const void *pChunk = pIn;
	int cbChunk = pPktEnd - pIn;

	// Decrypt it, and check packet number
	UDPRecvPacketContext_t ctx;
	ctx.m_usecNow = usecNow;
	ctx.m_pTransport = this;
	ctx.m_pStatsIn = pMsgStatsIn;
	if ( !m_connection.DecryptDataChunk( nWirePktNumber, cbPkt, pChunk, cbChunk, ctx ) )
		return;

	// This is a valid packet.  P2P connections might want to make a note of this
	RecvValidUDPDataPacket( ctx );

	// Process plaintext
	int usecTimeSinceLast = 0; // FIXME - should we plumb this through so we can measure jitter?
	if ( !m_connection.ProcessPlainTextDataChunk( usecTimeSinceLast, ctx ) )
		return;

	// Process the stats, if any
	if ( pMsgStatsIn )
		RecvStats( *pMsgStatsIn, usecNow );
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
void CConnectionTransportUDPBase::Received_Data( const uint8 *pPkt, int cbPkt, SteamNetworkingMicroseconds usecNow )
{

	if ( cbPkt < sizeof(UDPDataMsgHdr) )
	{
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Packet of size %d is too small.", cbPkt );
		return;
	}

	// Check cookie
	const UDPDataMsgHdr *hdr = (const UDPDataMsgHdr *)pPkt;
	if ( LittleDWord( hdr->m_unToConnectionID ) != ConnectionIDLocal() )
	{

		// Wrong session.  It could be an old session, or it could be spoofed.
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Incorrect connection ID" );
		if ( BCheckGlobalSpamReplyRateLimit( usecNow ) )
		{
			SendNoConnection( LittleDWord( hdr->m_unToConnectionID ), 0 );
		}
		return;
	}
	uint16 nWirePktNumber = LittleWord( hdr->m_unSeqNum );

	// Check state
	switch ( ConnectionState() )
	{
		case k_ESteamNetworkingConnectionState_Dead:
		case k_ESteamNetworkingConnectionState_None:
		default:
			Assert( false );
			return;

		case k_ESteamNetworkingConnectionState_ClosedByPeer:
		case k_ESteamNetworkingConnectionState_FinWait:
		case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
			SendConnectionClosedOrNoConnection();
			return;

		case k_ESteamNetworkingConnectionState_Connecting:
			// Ignore it.  We don't have the SteamID of whoever is on the other end yet,
			// their encryption keys, etc.  The most likely cause is that a server sent
			// a ConnectOK, which dropped.  So they think we're connected but we don't
			// have everything yet.
			return;

		case k_ESteamNetworkingConnectionState_Linger:
		case k_ESteamNetworkingConnectionState_Connected:
		case k_ESteamNetworkingConnectionState_FindingRoute: // not used for raw UDP, but might be used for derived class

			// We'll process the chunk
			break;
	}

	const uint8 *pIn = pPkt + sizeof(*hdr);
	const uint8 *pPktEnd = pPkt + cbPkt;

	// Inline stats?
	static CMsgSteamSockets_UDP_Stats msgStats;
	CMsgSteamSockets_UDP_Stats *pMsgStatsIn = nullptr;
	uint32 cbStatsMsgIn = 0;
	if ( hdr->m_unMsgFlags & hdr->kFlag_ProtobufBlob )
	{
		//Msg_Verbose( "Received inline stats from %s", server.m_szName );

		pIn = DeserializeVarInt( pIn, pPktEnd, cbStatsMsgIn );
		if ( pIn == NULL )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Failed to varint decode size of stats blob" );
			return;
		}
		if ( cbStatsMsgIn > pPktEnd - pIn )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "stats message size doesn't make sense.  Stats message size %u, packet size %d", cbStatsMsgIn, cbPkt );
			return;
		}

		if ( !msgStats.ParseFromArray( pIn, cbStatsMsgIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "protobuf failed to parse inline stats message" );
			return;
		}

		// Shove sequence number so we know what acks to pend, etc
		pMsgStatsIn = &msgStats;

		// Advance pointer
		pIn += cbStatsMsgIn;
	}

	const void *pChunk = pIn;
	int cbChunk = pPktEnd - pIn;

	// Decrypt it, and check packet number
	UDPRecvPacketContext_t ctx;
	ctx.m_usecNow = usecNow;
	ctx.m_pTransport = this;
	ctx.m_pStatsIn = pMsgStatsIn;
	if ( !m_connection.DecryptDataChunk( nWirePktNumber, cbPkt, pChunk, cbChunk, ctx ) )
		return;

	// This is a valid packet.  P2P connections might want to make a note of this
	RecvValidUDPDataPacket( ctx );

	// Process plaintext
	int usecTimeSinceLast = 0; // FIXME - should we plumb this through so we can measure jitter?
	if ( !m_connection.ProcessPlainTextDataChunk( usecTimeSinceLast, ctx ) )
		return;

	// Process the stats, if any
	if ( pMsgStatsIn )
		RecvStats( *pMsgStatsIn, usecNow );
}
````

### 候选（顺序已随机化）

#### PATCH-2B0DDBC187

````c
void CConnectionTransportUDPBase::Received_Data( const uint8 *pPkt, int cbPkt, SteamNetworkingMicroseconds usecNow )
{

	if ( cbPkt < (int)sizeof(UDPDataMsgHdr) )
	{
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Packet of size %d is too small.", cbPkt );
		return;
	}

	// Check cookie
	const UDPDataMsgHdr *hdr = (const UDPDataMsgHdr *)pPkt;
	if ( LittleDWord( hdr->m_unToConnectionID ) != ConnectionIDLocal() )
	{

		// Wrong session.  It could be an old session, or it could be spoofed.
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Incorrect connection ID" );
		if ( BCheckGlobalSpamReplyRateLimit( usecNow ) )
		{
			SendNoConnection( LittleDWord( hdr->m_unToConnectionID ), 0 );
		}
		return;
	}
	uint16 nWirePktNumber = LittleWord( hdr->m_unSeqNum );

	// Check state
	switch ( ConnectionState() )
	{
		case k_ESteamNetworkingConnectionState_Dead:
		case k_ESteamNetworkingConnectionState_None:
		default:
			Assert( false );
			return;

		case k_ESteamNetworkingConnectionState_ClosedByPeer:
		case k_ESteamNetworkingConnectionState_FinWait:
		case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
			SendConnectionClosedOrNoConnection();
			return;

		case k_ESteamNetworkingConnectionState_Connecting:
			// Ignore it.  We don't have the SteamID of whoever is on the other end yet,
			// their encryption keys, etc.  The most likely cause is that a server sent
			// a ConnectOK, which dropped.  So they think we're connected but we don't
			// have everything yet.
			return;

		case k_ESteamNetworkingConnectionState_Linger:
		case k_ESteamNetworkingConnectionState_Connected:
		case k_ESteamNetworkingConnectionState_FindingRoute: // not used for raw UDP, but might be used for derived class

			// We'll process the chunk
			break;
	}

	const uint8 *pIn = pPkt + sizeof(*hdr);
	const uint8 *pPktEnd = pPkt + cbPkt;

	// Inline stats?
	static CMsgSteamSockets_UDP_Stats msgStats;
	CMsgSteamSockets_UDP_Stats *pMsgStatsIn = nullptr;
	uint32 cbStatsMsgIn = 0;
	if ( hdr->m_unMsgFlags & hdr->kFlag_ProtobufBlob )
	{
		//Msg_Verbose( "Received inline stats from %s", server.m_szName );

		pIn = DeserializeVarInt( pIn, pPktEnd, cbStatsMsgIn );
		if ( pIn == NULL )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Failed to varint decode size of stats blob" );
			return;
		}
		if ( cbStatsMsgIn > (uint32)( pPktEnd - pIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "stats message size doesn't make sense.  Stats message size %d, packet size %d", cbStatsMsgIn, cbPkt );
			return;
		}

		if ( !msgStats.ParseFromArray( pIn, cbStatsMsgIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "protobuf failed to parse inline stats message" );
			return;
		}

		// Shove sequence number so we know what acks to pend, etc
		pMsgStatsIn = &msgStats;

		// Advance pointer
		pIn += cbStatsMsgIn;
	}

	const void *pChunk = pIn;
	int cbChunk = pPktEnd - pIn;

	// Decrypt it, and check packet number
	UDPRecvPacketContext_t ctx;
	ctx.m_usecNow = usecNow;
	ctx.m_pTransport = this;
	ctx.m_pStatsIn = pMsgStatsIn;
	if ( !m_connection.DecryptDataChunk( nWirePktNumber, cbPkt, pChunk, cbChunk, ctx ) )
		return;

	// This is a valid packet.  P2P connections might want to make a note of this
	RecvValidUDPDataPacket( ctx );

	// Process plaintext
	int usecTimeSinceLast = 0; // FIXME - should we plumb this through so we can measure jitter?
	if ( !m_connection.ProcessPlainTextDataChunk( usecTimeSinceLast, ctx ) )
		return;

	// Process the stats, if any
	if ( pMsgStatsIn )
		RecvStats( *pMsgStatsIn, usecNow );
}
````

**模型解释**

````c
The original bounds check `pIn + cbStatsMsgIn > pPktEnd` can overflow the pointer arithmetic when cbStatsMsgIn is large, allowing an out-of-bounds read in ParseFromArray. The fix compares cbStatsMsgIn against the remaining byte count (pPktEnd - pIn) instead, which cannot overflow and correctly rejects oversized stats blobs.
````

#### PATCH-7A8A85918C

````c
void CConnectionTransportUDPBase::Received_Data( const uint8 *pPkt, int cbPkt, SteamNetworkingMicroseconds usecNow )
{

	if ( cbPkt < sizeof(UDPDataMsgHdr) )
	{
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Packet of size %d is too small.", cbPkt );
		return;
	}

	// Check cookie
	const UDPDataMsgHdr *hdr = (const UDPDataMsgHdr *)pPkt;
	if ( LittleDWord( hdr->m_unToConnectionID ) != ConnectionIDLocal() )
	{

		// Wrong session.  It could be an old session, or it could be spoofed.
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Incorrect connection ID" );
		if ( BCheckGlobalSpamReplyRateLimit( usecNow ) )
		{
			SendNoConnection( LittleDWord( hdr->m_unToConnectionID ), 0 );
		}
		return;
	}
	uint16 nWirePktNumber = LittleWord( hdr->m_unSeqNum );

	// Check state
	switch ( ConnectionState() )
	{
		case k_ESteamNetworkingConnectionState_Dead:
		case k_ESteamNetworkingConnectionState_None:
		default:
			Assert( false );
			return;

		case k_ESteamNetworkingConnectionState_ClosedByPeer:
		case k_ESteamNetworkingConnectionState_FinWait:
		case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
			SendConnectionClosedOrNoConnection();
			return;

		case k_ESteamNetworkingConnectionState_Connecting:
			// Ignore it.  We don't have the SteamID of whoever is on the other end yet,
			// their encryption keys, etc.  The most likely cause is that a server sent
			// a ConnectOK, which dropped.  So they think we're connected but we don't
			// have everything yet.
			return;

		case k_ESteamNetworkingConnectionState_Linger:
		case k_ESteamNetworkingConnectionState_Connected:
		case k_ESteamNetworkingConnectionState_FindingRoute: // not used for raw UDP, but might be used for derived class

			// We'll process the chunk
			break;
	}

	const uint8 *pIn = pPkt + sizeof(*hdr);
	const uint8 *pPktEnd = pPkt + cbPkt;

	// Inline stats?
	static CMsgSteamSockets_UDP_Stats msgStats;
	CMsgSteamSockets_UDP_Stats *pMsgStatsIn = nullptr;
	uint32 cbStatsMsgIn = 0;
	if ( hdr->m_unMsgFlags & hdr->kFlag_ProtobufBlob )
	{
		//Msg_Verbose( "Received inline stats from %s", server.m_szName );

		pIn = DeserializeVarInt( pIn, pPktEnd, cbStatsMsgIn );
		if ( pIn == NULL )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Failed to varint decode size of stats blob" );
			return;
		}
		if ( cbStatsMsgIn > (uint32)( pPktEnd - pIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "stats message size doesn't make sense.  Stats message size %d, packet size %d", cbStatsMsgIn, cbPkt );
			return;
		}

		if ( !msgStats.ParseFromArray( pIn, cbStatsMsgIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "protobuf failed to parse inline stats message" );
			return;
		}

		// Shove sequence number so we know what acks to pend, etc
		pMsgStatsIn = &msgStats;

		// Advance pointer
		pIn += cbStatsMsgIn;
	}

	const void *pChunk = pIn;
	int cbChunk = pPktEnd - pIn;

	// Decrypt it, and check packet number
	UDPRecvPacketContext_t ctx;
	ctx.m_usecNow = usecNow;
	ctx.m_pTransport = this;
	ctx.m_pStatsIn = pMsgStatsIn;
	if ( !m_connection.DecryptDataChunk( nWirePktNumber, cbPkt, pChunk, cbChunk, ctx ) )
		return;

	// This is a valid packet.  P2P connections might want to make a note of this
	RecvValidUDPDataPacket( ctx );

	// Process plaintext
	int usecTimeSinceLast = 0; // FIXME - should we plumb this through so we can measure jitter?
	if ( !m_connection.ProcessPlainTextDataChunk( usecTimeSinceLast, ctx ) )
		return;

	// Process the stats, if any
	if ( pMsgStatsIn )
		RecvStats( *pMsgStatsIn, usecNow );
}
````

**模型解释**

````c
The original bounds check `pIn + cbStatsMsgIn > pPktEnd` can overflow the pointer arithmetic when cbStatsMsgIn is large, bypassing the check and leading to out-of-bounds reads in ParseFromArray. Replaced it with a subtraction-based check `cbStatsMsgIn > (uint32)(pPktEnd - pIn)`, which cannot overflow and correctly validates that the stats blob fits within the packet.
````

#### PATCH-F24E67EE58

````c
void CConnectionTransportUDPBase::Received_Data( const uint8 *pPkt, int cbPkt, SteamNetworkingMicroseconds usecNow )
{

	if ( cbPkt < (int)sizeof(UDPDataMsgHdr) )
	{
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Packet of size %d is too small.", cbPkt );
		return;
	}

	// Check cookie
	const UDPDataMsgHdr *hdr = (const UDPDataMsgHdr *)pPkt;
	if ( LittleDWord( hdr->m_unToConnectionID ) != ConnectionIDLocal() )
	{

		// Wrong session.  It could be an old session, or it could be spoofed.
		ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Incorrect connection ID" );
		if ( BCheckGlobalSpamReplyRateLimit( usecNow ) )
		{
			SendNoConnection( LittleDWord( hdr->m_unToConnectionID ), 0 );
		}
		return;
	}
	uint16 nWirePktNumber = LittleWord( hdr->m_unSeqNum );

	// Check state
	switch ( ConnectionState() )
	{
		case k_ESteamNetworkingConnectionState_Dead:
		case k_ESteamNetworkingConnectionState_None:
		default:
			Assert( false );
			return;

		case k_ESteamNetworkingConnectionState_ClosedByPeer:
		case k_ESteamNetworkingConnectionState_FinWait:
		case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
			SendConnectionClosedOrNoConnection();
			return;

		case k_ESteamNetworkingConnectionState_Connecting:
			// Ignore it.  We don't have the SteamID of whoever is on the other end yet,
			// their encryption keys, etc.  The most likely cause is that a server sent
			// a ConnectOK, which dropped.  So they think we're connected but we don't
			// have everything yet.
			return;

		case k_ESteamNetworkingConnectionState_Linger:
		case k_ESteamNetworkingConnectionState_Connected:
		case k_ESteamNetworkingConnectionState_FindingRoute: // not used for raw UDP, but might be used for derived class

			// We'll process the chunk
			break;
	}

	const uint8 *pIn = pPkt + sizeof(*hdr);
	const uint8 *pPktEnd = pPkt + cbPkt;

	// Inline stats?
	static CMsgSteamSockets_UDP_Stats msgStats;
	CMsgSteamSockets_UDP_Stats *pMsgStatsIn = nullptr;
	uint32 cbStatsMsgIn = 0;
	if ( hdr->m_unMsgFlags & hdr->kFlag_ProtobufBlob )
	{
		//Msg_Verbose( "Received inline stats from %s", server.m_szName );

		pIn = DeserializeVarInt( pIn, pPktEnd, cbStatsMsgIn );
		if ( pIn == NULL )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "Failed to varint decode size of stats blob" );
			return;
		}
		if ( cbStatsMsgIn > (uint32)( pPktEnd - pIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "stats message size doesn't make sense.  Stats message size %d, packet size %d", cbStatsMsgIn, cbPkt );
			return;
		}

		if ( !msgStats.ParseFromArray( pIn, cbStatsMsgIn ) )
		{
			ReportBadUDPPacketFromConnectionPeer( "DataPacket", "protobuf failed to parse inline stats message" );
			return;
		}

		// Shove sequence number so we know what acks to pend, etc
		pMsgStatsIn = &msgStats;

		// Advance pointer
		pIn += cbStatsMsgIn;
	}

	const void *pChunk = pIn;
	int cbChunk = pPktEnd - pIn;

	// Decrypt it, and check packet number
	UDPRecvPacketContext_t ctx;
	ctx.m_usecNow = usecNow;
	ctx.m_pTransport = this;
	ctx.m_pStatsIn = pMsgStatsIn;
	if ( !m_connection.DecryptDataChunk( nWirePktNumber, cbPkt, pChunk, cbChunk, ctx ) )
		return;

	// This is a valid packet.  P2P connections might want to make a note of this
	RecvValidUDPDataPacket( ctx );

	// Process plaintext
	int usecTimeSinceLast = 0; // FIXME - should we plumb this through so we can measure jitter?
	if ( !m_connection.ProcessPlainTextDataChunk( usecTimeSinceLast, ctx ) )
		return;

	// Process the stats, if any
	if ( pMsgStatsIn )
		RecvStats( *pMsgStatsIn, usecNow );
}
````

**模型解释**

````c
The vulnerable check `pIn + cbStatsMsgIn > pPktEnd` can overflow the pointer arithmetic, allowing an out-of-bounds read. The fix compares the stats size against the remaining bytes (`pPktEnd - pIn`) instead, which cannot overflow.
````

---

## CASE-8F4CEBDDB4 — NVD-CWE-Other / unknown

### 漏洞函数

````c
check_1_6_dummy(kadm5_principal_ent_t entry, long mask,
                int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char **passptr)
{
    int i;
    char *password = *passptr;

    /* Old-style randkey operations disallowed tickets to start. */
    if (!(mask & KADM5_ATTRIBUTES) ||
        !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX))
        return;

    /* The 1.6 dummy password was the octets 1..255. */
    for (i = 0; (unsigned char) password[i] == i + 1; i++);
    if (password[i] != '\0' || i != 255)
        return;

    /* This will make the caller use a random password instead. */
    *passptr = NULL;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
check_1_6_dummy(kadm5_principal_ent_t entry, long mask,
                int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char **passptr)
{
    int i;
    char *password = *passptr;

    /* Old-style randkey operations disallowed tickets to start. */
    if (password == NULL || !(mask & KADM5_ATTRIBUTES) ||
        !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX))
        return;

    /* The 1.6 dummy password was the octets 1..255. */
    for (i = 0; (unsigned char) password[i] == i + 1; i++);
    if (password[i] != '\0' || i != 255)
        return;

    /* This will make the caller use a random password instead. */
    *passptr = NULL;
}
````

### 候选（顺序已随机化）

#### PATCH-CA2AAD4606

````c
check_1_6_dummy(kadm5_principal_ent_t entry, long mask,
                int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char **passptr)
{
    int i;
    char *password = *passptr;

    /* Old-style randkey operations disallowed tickets to start. */
    if (!(mask & KADM5_ATTRIBUTES) ||
        !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX))
        return;

    /* The 1.6 dummy password was the octets 1..255. */
    for (i = 0; (unsigned char) password[i] == i + 1; i++);
    if (password[i] != '\0' || i != 255)
        return;

    /* This will make the caller use a random password instead. */
    *passptr = NULL;
}
````

**模型解释**

````c
The loop reads password[i] without first checking that the string is long enough. The fix bounds the scan to 255 bytes so it cannot read past the end of a shorter password buffer.
````

#### PATCH-B5D725561F

````c
check_1_6_dummy(kadm5_principal_ent_t entry, long mask,
                int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char **passptr)
{
    int i;
    char *password = *passptr;

    /* Old-style randkey operations disallowed tickets to start. */
    if (!(mask & KADM5_ATTRIBUTES) ||
        !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX))
        return;

    if (password == NULL)
        return;

    /* The 1.6 dummy password was the octets 1..255. */
    for (i = 0; i < 255; i++) {
        if ((unsigned char) password[i] != i + 1)
            return;
    }
    if (password[255] != '\0')
        return;

    /* This will make the caller use a random password instead. */
    *passptr = NULL;
}
````

**模型解释**

````c
The original loop could read past the end of the password buffer if it contained the expected prefix but lacked a terminating NUL, and it dereferenced a potentially NULL password. The fixed version checks for NULL and bounds the loop to exactly 255 bytes before verifying the terminator, preventing out-of-bounds reads while preserving the intended detection of the 1.6 dummy password.
````

---

## CASE-BF50803A62 — CWE-770 / resource

### 漏洞函数

````c
setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection = createDummyConnection(65535, &sentData);
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection =
        createDummyConnection(UA_ConnectionConfig_default.sendBufferSize, &sentData);
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
````

### 候选（顺序已随机化）

#### PATCH-8C9E20C078

````c
setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection = createDummyConnection(65535, &sentData);
    if(!testingConnection)
        return;
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
````

**模型解释**

````c
The original code dereferences the result of createDummyConnection without checking for NULL, which can cause a null-pointer dereference. The fix adds a NULL check and returns early if connection creation fails.
````

#### PATCH-9750DF1AEC

````c
setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection = createDummyConnection(65535, &sentData);
    if(testingConnection == NULL)
        return;
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
````

**模型解释**

````c
Added a NULL check after createDummyConnection to prevent a null-pointer dereference when connection creation fails, while preserving the original behavior otherwise.
````

#### PATCH-3443318B63

````c
void setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection = createDummyConnection(65535, &sentData);
    if(testingConnection == NULL)
        return;
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
````

**模型解释**

````c
Added a NULL check after createDummyConnection to prevent dereferencing a failed allocation, and made the function return type explicit (void). The intended behavior is preserved when connection creation succeeds.
````

---

## CASE-533FB0E13C — CWE-369CWE-190 / integer

### 漏洞函数

````c
png_check_chunk_length(png_const_structrp png_ptr, const png_uint_32 length)
{
   png_alloc_size_t limit = PNG_UINT_31_MAX;

# ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (png_ptr->user_chunk_malloc_max > 0 &&
       png_ptr->user_chunk_malloc_max < limit)
      limit = png_ptr->user_chunk_malloc_max;
# elif PNG_USER_CHUNK_MALLOC_MAX > 0
   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
      limit = PNG_USER_CHUNK_MALLOC_MAX;
# endif
   if (png_ptr->chunk_name == png_IDAT)
   {
      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      size_t row_factor =
         (png_ptr->width * png_ptr->channels * (png_ptr->bit_depth > 8? 2: 1)
          + 1 + (png_ptr->interlaced? 6: 0));
      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
         idat_limit=PNG_UINT_31_MAX;
      else
         idat_limit = png_ptr->height * row_factor;
      row_factor = row_factor > 32566? 32566 : row_factor;
      idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */
      idat_limit=idat_limit < PNG_UINT_31_MAX? idat_limit : PNG_UINT_31_MAX;
      limit = limit < idat_limit? idat_limit : limit;
   }

   if (length > limit)
   {
      png_debug2(0," length = %lu, limit = %lu",
         (unsigned long)length,(unsigned long)limit);
      png_chunk_error(png_ptr, "chunk data is too large");
   }
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
png_check_chunk_length(png_const_structrp png_ptr, const png_uint_32 length)
{
   png_alloc_size_t limit = PNG_UINT_31_MAX;

# ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (png_ptr->user_chunk_malloc_max > 0 &&
       png_ptr->user_chunk_malloc_max < limit)
      limit = png_ptr->user_chunk_malloc_max;
# elif PNG_USER_CHUNK_MALLOC_MAX > 0
   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
      limit = PNG_USER_CHUNK_MALLOC_MAX;
# endif
   if (png_ptr->chunk_name == png_IDAT)
   {
      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      size_t row_factor =
         (size_t)png_ptr->width
         * (size_t)png_ptr->channels
         * (png_ptr->bit_depth > 8? 2: 1)
         + 1
         + (png_ptr->interlaced? 6: 0);
      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
         idat_limit = PNG_UINT_31_MAX;
      else
         idat_limit = png_ptr->height * row_factor;
      row_factor = row_factor > 32566? 32566 : row_factor;
      idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */
      idat_limit=idat_limit < PNG_UINT_31_MAX? idat_limit : PNG_UINT_31_MAX;
      limit = limit < idat_limit? idat_limit : limit;
   }

   if (length > limit)
   {
      png_debug2(0," length = %lu, limit = %lu",
         (unsigned long)length,(unsigned long)limit);
      png_chunk_error(png_ptr, "chunk data is too large");
   }
}
````

### 候选（顺序已随机化）

#### PATCH-ABDF7A46AC

````c
png_check_chunk_length(png_const_structrp png_ptr, const png_uint_32 length)
{
   png_alloc_size_t limit = PNG_UINT_31_MAX;

# ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (png_ptr->user_chunk_malloc_max > 0 &&
       png_ptr->user_chunk_malloc_max < limit)
      limit = png_ptr->user_chunk_malloc_max;
# elif PNG_USER_CHUNK_MALLOC_MAX > 0
   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
      limit = PNG_USER_CHUNK_MALLOC_MAX;
# endif
   if (png_ptr->chunk_name == png_IDAT)
   {
      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      size_t row_factor =
         (png_ptr->width * png_ptr->channels * (png_ptr->bit_depth > 8? 2: 1)
          + 1 + (png_ptr->interlaced? 6: 0));
      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
         idat_limit=PNG_UINT_31_MAX;
      else
         idat_limit = png_ptr->height * row_factor;
      row_factor = row_factor > 32566? 32566 : row_factor;
      idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */
      idat_limit=idat_limit < PNG_UINT_31_MAX? idat_limit : PNG_UINT_31_MAX;
      limit = limit < idat_limit? idat_limit : limit;
   }

   if (length > limit)
   {
      png_debug2(0," length = %lu, limit = %lu",
         (unsigned long)length,(unsigned long)limit);
      png_chunk_error(png_ptr, "chunk data is too large");
   }
}
````

**模型解释**

````c
The IDAT limit calculation can overflow: width*channels*bytes-per-pixel is computed in size_t and may wrap, and the height*row_factor product can also overflow before the comparison. The fix guards the row_factor computation against overflow and uses a division-based check so the limit is computed safely.
````

#### PATCH-E6BE5F831E

````c
png_check_chunk_length(png_const_structrp png_ptr, const png_uint_32 length)
{
   png_alloc_size_t limit = PNG_UINT_31_MAX;

# ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (png_ptr->user_chunk_malloc_max > 0 &&
       png_ptr->user_chunk_malloc_max < limit)
      limit = png_ptr->user_chunk_malloc_max;
# elif PNG_USER_CHUNK_MALLOC_MAX > 0
   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
      limit = PNG_USER_CHUNK_MALLOC_MAX;
# endif
   if (png_ptr->chunk_name == png_IDAT)
   {
      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      png_alloc_size_t row_factor =
         (png_alloc_size_t)png_ptr->width * png_ptr->channels *
         (png_ptr->bit_depth > 8? 2: 1);

      if (row_factor > PNG_UINT_31_MAX - 1 - (png_ptr->interlaced? 6: 0))
         row_factor = PNG_UINT_31_MAX;
      else
         row_factor += 1 + (png_ptr->interlaced? 6: 0);

      if (row_factor > 0 && png_ptr->height > PNG_UINT_31_MAX/row_factor)
         idat_limit = PNG_UINT_31_MAX;
      else
         idat_limit = (png_alloc_size_t)png_ptr->height * row_factor;

      if (row_factor > 32566)
         row_factor = 32566;

      if (idat_limit > PNG_UINT_31_MAX - (6 + 5*(idat_limit/row_factor+1)))
         idat_limit = PNG_UINT_31_MAX;
      else
         idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */

      if (idat_limit > PNG_UINT_31_MAX)
         idat_limit = PNG_UINT_31_MAX;

      if (limit < idat_limit)
         limit = idat_limit;
   }

   if (length > limit)
   {
      png_debug2(0," length = %lu, limit = %lu",
         (unsigned long)length,(unsigned long)limit);
      png_chunk_error(png_ptr, "chunk data is too large");
   }
}
````

**模型解释**

````c
The original code computed row_factor using size_t arithmetic that could overflow on 32-bit platforms (width*channels*bytes_per_sample), and the subsequent height*row_factor and overhead additions could also overflow. The fix performs the multiplications in png_alloc_size_t with explicit overflow checks before each addition/multiplication, clamps row_factor to 32566 before division, and ensures idat_limit never exceeds PNG_UINT_31_MAX, preserving the intended limit-checking behavior while eliminating integer overflow.
````

#### PATCH-33824DD89C

````c
png_check_chunk_length(png_const_structrp png_ptr, const png_uint_32 length)
{
   png_alloc_size_t limit = PNG_UINT_31_MAX;

# ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (png_ptr->user_chunk_malloc_max > 0 &&
       png_ptr->user_chunk_malloc_max < limit)
      limit = png_ptr->user_chunk_malloc_max;
# elif PNG_USER_CHUNK_MALLOC_MAX > 0
   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
      limit = PNG_USER_CHUNK_MALLOC_MAX;
# endif
   if (png_ptr->chunk_name == png_IDAT)
   {
      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      png_alloc_size_t row_factor =
         (png_alloc_size_t)png_ptr->width * png_ptr->channels *
         (png_ptr->bit_depth > 8? 2: 1);

      if (row_factor > PNG_UINT_31_MAX - 1 - (png_ptr->interlaced? 6: 0))
         row_factor = PNG_UINT_31_MAX;
      else
         row_factor += 1 + (png_ptr->interlaced? 6: 0);

      if (row_factor == 0 || png_ptr->height > PNG_UINT_31_MAX/row_factor)
         idat_limit = PNG_UINT_31_MAX;
      else
         idat_limit = png_ptr->height * row_factor;

      if (row_factor > 32566)
         row_factor = 32566;

      if (idat_limit > PNG_UINT_31_MAX - (6 + 5*(idat_limit/row_factor+1)))
         idat_limit = PNG_UINT_31_MAX;
      else
         idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */

      idat_limit = idat_limit < PNG_UINT_31_MAX? idat_limit : PNG_UINT_31_MAX;
      limit = limit < idat_limit? idat_limit : limit;
   }

   if (length > limit)
   {
      png_debug2(0," length = %lu, limit = %lu",
         (unsigned long)length,(unsigned long)limit);
      png_chunk_error(png_ptr, "chunk data is too large");
   }
}
````

**模型解释**

````c
The original code computed row_factor using size_t arithmetic that could overflow (width * channels * bytes-per-pixel), and the subsequent idat_limit addition could also overflow. The fix performs the multiplication in png_alloc_size_t with explicit overflow checks, clamps row_factor before use, and guards the zlib/deflate overhead addition against overflow, preserving the intended limit computation while preventing integer overflow.
````

---

## CASE-CABD0EA8AE — CWE-264 / access_control

### 漏洞函数

````c
static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0)
                        t->last_trigger.realtime = timespec_load(&st.st_atim);
                else if (errno == ENOENT)
                        /* The timer has never run before,
                         * make sure a stamp file exists.
                         */
                        touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 1;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0)
                        t->last_trigger.realtime = timespec_load(&st.st_atim);
                else if (errno == ENOENT)
                        /* The timer has never run before,
                         * make sure a stamp file exists.
                         */
                        touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 1;
}
````

### 候选（顺序已随机化）

#### PATCH-55E94F78A9

````c
static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0)
                        t->last_trigger.realtime = timespec_load(&st.st_atim);
                else if (errno == ENOENT)
                        /* The timer has never run before,
                         * make sure a stamp file exists.
                         */
                        (void) touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 1;
}
````

**模型解释**

````c
The vulnerable version ignores the return value of touch_file(), which can fail and leave the timer in an inconsistent state. The fix explicitly discards the result with a cast, making the intentional ignore clear while preserving behavior.
````

#### PATCH-A778E07106

````c
static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0)
                        t->last_trigger.realtime = timespec_load(&st.st_atim);
                else if (errno == ENOENT)
                        /* The timer has never run before,
                         * make sure a stamp file exists.
                         */
                        (void) touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 1;
}
````

**模型解释**

````c
The original code ignored the return value of touch_file(), which can fail (e.g., due to permissions or I/O errors) and leave the timer in an inconsistent state. The fix explicitly casts the result to void to document that the failure is intentionally ignored, preserving the original behavior while making the unchecked return explicit and avoiding compiler warnings. No other security-relevant defects (such as buffer overflows or injection) are present in this function.
````

#### PATCH-14BAA31E5B

````c
static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0)
                        t->last_trigger.realtime = timespec_load(&st.st_atim);
                else if (errno == ENOENT)
                        /* The timer has never run before,
                         * make sure a stamp file exists.
                         */
                        (void) touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 1;
}
````

**模型解释**

````c
The original code ignored the return value of touch_file, which can fail (e.g., due to permissions or races) and leave the timer in an inconsistent state. The fix explicitly casts the result to void to document that the failure is intentionally ignored, preserving the original behavior while making the unchecked call explicit and avoiding compiler warnings. No security-relevant behavior is changed beyond clarifying the ignored result.
````

---

## CASE-94465F15EE — NVD-CWE-noinfo / unknown

### 漏洞函数

````c
int sqlite3CheckObjectName(
  Parse *pParse,            /* Parsing context */
  const char *zName,        /* Name of the object to check */
  const char *zType,        /* Type of this object */
  const char *zTblName      /* Parent table name for triggers and indexes */
){
  sqlite3 *db = pParse->db;
  if( sqlite3WritableSchema(db) || db->init.imposterTable ){
    /* Skip these error checks for writable_schema=ON */
    return SQLITE_OK;
  }
  if( db->init.busy ){
    if( sqlite3_stricmp(zType, db->init.azInit[0])
     || sqlite3_stricmp(zName, db->init.azInit[1])
     || sqlite3_stricmp(zTblName, db->init.azInit[2])
    ){
      if( sqlite3Config.bExtraSchemaChecks ){
        sqlite3ErrorMsg(pParse, ""); /* corruptSchema() will supply the error */
        return SQLITE_ERROR;
      }
    }
  }else{
    if( pParse->nested==0 
     && 0==sqlite3StrNICmp(zName, "sqlite_", 7)
    ){
      sqlite3ErrorMsg(pParse, "object name reserved for internal use: %s",
                      zName);
      return SQLITE_ERROR;
    }
  }
  return SQLITE_OK;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
int sqlite3CheckObjectName(
  Parse *pParse,            /* Parsing context */
  const char *zName,        /* Name of the object to check */
  const char *zType,        /* Type of this object */
  const char *zTblName      /* Parent table name for triggers and indexes */
){
  sqlite3 *db = pParse->db;
  if( sqlite3WritableSchema(db) || db->init.imposterTable ){
    /* Skip these error checks for writable_schema=ON */
    return SQLITE_OK;
  }
  if( db->init.busy ){
    if( sqlite3_stricmp(zType, db->init.azInit[0])
     || sqlite3_stricmp(zName, db->init.azInit[1])
     || sqlite3_stricmp(zTblName, db->init.azInit[2])
    ){
      if( sqlite3Config.bExtraSchemaChecks ){
        sqlite3ErrorMsg(pParse, ""); /* corruptSchema() will supply the error */
        return SQLITE_ERROR;
      }
    }
  }else{
    if( (pParse->nested==0 && 0==sqlite3StrNICmp(zName, "sqlite_", 7))
     || (sqlite3ReadOnlyShadowTables(db) && sqlite3ShadowTableName(db, zName))
    ){
      sqlite3ErrorMsg(pParse, "object name reserved for internal use: %s",
                      zName);
      return SQLITE_ERROR;
    }

  }
  return SQLITE_OK;
}
````

### 候选（顺序已随机化）

#### PATCH-701CC5A91F

````c
int sqlite3CheckObjectName(
  Parse *pParse,            /* Parsing context */
  const char *zName,        /* Name of the object to check */
  const char *zType,        /* Type of this object */
  const char *zTblName      /* Parent table name for triggers and indexes */
){
  sqlite3 *db = pParse->db;
  if( sqlite3WritableSchema(db) || db->init.imposterTable ){
    /* Skip these error checks for writable_schema=ON */
    return SQLITE_OK;
  }
  if( db->init.busy ){
    if( sqlite3_stricmp(zType, db->init.azInit[0])
     || sqlite3_stricmp(zName, db->init.azInit[1])
     || sqlite3_stricmp(zTblName, db->init.azInit[2])
    ){
      if( sqlite3Config.bExtraSchemaChecks ){
        sqlite3ErrorMsg(pParse, ""); /* corruptSchema() will supply the error */
        return SQLITE_ERROR;
      }
    }
  }else{
    if( pParse->nested==0 
     && 0==sqlite3StrNICmp(zName, "sqlite_", 7)
    ){
      sqlite3ErrorMsg(pParse, "object name reserved for internal use: %s",
                      zName);
      return SQLITE_ERROR;
    }
  }
  return SQLITE_OK;
}
````

**模型解释**

````c
The function already performs the intended reserved-name check and schema validation; no memory-safety defect is present in the supplied code, so the function is preserved unchanged.
````

#### PATCH-1B8B915631

````c
int sqlite3CheckObjectName(
  Parse *pParse,            /* Parsing context */
  const char *zName,        /* Name of the object to check */
  const char *zType,        /* Type of this object */
  const char *zTblName      /* Parent table name for triggers and indexes */
){
  sqlite3 *db = pParse->db;
  if( sqlite3WritableSchema(db) || db->init.imposterTable ){
    /* Skip these error checks for writable_schema=ON */
    return SQLITE_OK;
  }
  if( db->init.busy ){
    if( sqlite3_stricmp(zType, db->init.azInit[0])
     || sqlite3_stricmp(zName, db->init.azInit[1])
     || sqlite3_stricmp(zTblName, db->init.azInit[2])
    ){
      if( sqlite3Config.bExtraSchemaChecks ){
        sqlite3ErrorMsg(pParse, ""); /* corruptSchema() will supply the error */
        return SQLITE_ERROR;
      }
    }
  }else{
    if( pParse->nested==0 
     && 0==sqlite3StrNICmp(zName, "sqlite_", 7)
    ){
      sqlite3ErrorMsg(pParse, "object name reserved for internal use: %s",
                      zName);
      return SQLITE_ERROR;
    }
  }
  return SQLITE_OK;
}
````

**模型解释**

````c
The function is already safe: it only compares names and reports an error, with no buffer overflow, format-string, or memory-safety defect. The replacement preserves the original behavior and signature unchanged.
````

---

## CASE-7D5DA88F1F — CWE-120 / memory_buffer

### 漏洞函数

````c
static void dbEvalSetColumnJSON(DbEvalContext *p, int iCol, Jsi_DString *dStr) {
    Jsi_Interp *interp = p->jdb->interp;
    char nbuf[200];

    sqlite3_stmt *pStmt = p->pPreStmt->pStmt;

    switch( sqlite3_column_type(pStmt, iCol) ) {
    case SQLITE_BLOB: {
        int bytes = sqlite3_column_bytes(pStmt, iCol);
        const char *zBlob = (char*)sqlite3_column_blob(pStmt, iCol);
        if( !zBlob ) {
            Jsi_DSAppend(dStr, "null", NULL);
            return;
        }
        Jsi_JSONQuote(interp, zBlob, bytes, dStr);
        return;
    }
    case SQLITE_INTEGER: {
        sqlite_int64 v = sqlite3_column_int64(pStmt, iCol);
        if (v==0 || v==1) {
            const char *dectyp = sqlite3_column_decltype(pStmt, iCol);
            if (dectyp && !Jsi_Strncasecmp(dectyp,"bool", 4)) {
                Jsi_DSAppend(dStr, (v?"true":"false"), NULL);
                return;
            }
        }
#ifdef __WIN32
        snprintf(nbuf, sizeof(nbuf), "%" PRId64, (Jsi_Wide)v);
#else
        snprintf(nbuf, sizeof(nbuf), "%lld", v);
#endif
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_FLOAT: {
        Jsi_NumberToString(interp, sqlite3_column_double(pStmt, iCol), nbuf, sizeof(nbuf));
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_NULL: {
        Jsi_DSAppend(dStr, "null", NULL);
        return;
    }
    }
    const char *str = (char*)sqlite3_column_text(pStmt, iCol );
    if (!str)
        str = p->jdb->optPtr->nullvalue;
    Jsi_JSONQuote(interp, str?str:"", -1, dStr);
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static void dbEvalSetColumnJSON(DbEvalContext *p, int iCol, Jsi_DString *dStr) {
    Jsi_Interp *interp = p->jdb->interp;
    char nbuf[JSI_MAX_NUMBER_STRING];

    sqlite3_stmt *pStmt = p->pPreStmt->pStmt;

    switch( sqlite3_column_type(pStmt, iCol) ) {
    case SQLITE_BLOB: {
        int bytes = sqlite3_column_bytes(pStmt, iCol);
        const char *zBlob = (char*)sqlite3_column_blob(pStmt, iCol);
        if( !zBlob ) {
            Jsi_DSAppend(dStr, "null", NULL);
            return;
        }
        Jsi_JSONQuote(interp, zBlob, bytes, dStr);
        return;
    }
    case SQLITE_INTEGER: {
        sqlite_int64 v = sqlite3_column_int64(pStmt, iCol);
        if (v==0 || v==1) {
            const char *dectyp = sqlite3_column_decltype(pStmt, iCol);
            if (dectyp && !Jsi_Strncasecmp(dectyp,"bool", 4)) {
                Jsi_DSAppend(dStr, (v?"true":"false"), NULL);
                return;
            }
        }
#ifdef __WIN32
        snprintf(nbuf, sizeof(nbuf), "%" PRId64, (Jsi_Wide)v);
#else
        snprintf(nbuf, sizeof(nbuf), "%lld", v);
#endif
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_FLOAT: {
        Jsi_NumberToString(interp, sqlite3_column_double(pStmt, iCol), nbuf, sizeof(nbuf));
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_NULL: {
        Jsi_DSAppend(dStr, "null", NULL);
        return;
    }
    }
    const char *str = (char*)sqlite3_column_text(pStmt, iCol );
    if (!str)
        str = p->jdb->optPtr->nullvalue;
    Jsi_JSONQuote(interp, str?str:"", -1, dStr);
}
````

### 候选（顺序已随机化）

#### PATCH-BDC447DFBD

````c
static void dbEvalSetColumnJSON(DbEvalContext *p, int iCol, Jsi_DString *dStr) {
    Jsi_Interp *interp = p->jdb->interp;
    char nbuf[200];

    sqlite3_stmt *pStmt = p->pPreStmt->pStmt;

    switch( sqlite3_column_type(pStmt, iCol) ) {
    case SQLITE_BLOB: {
        int bytes = sqlite3_column_bytes(pStmt, iCol);
        const char *zBlob = (char*)sqlite3_column_blob(pStmt, iCol);
        if( !zBlob ) {
            Jsi_DSAppend(dStr, "null", NULL);
            return;
        }
        Jsi_JSONQuote(interp, zBlob, bytes, dStr);
        return;
    }
    case SQLITE_INTEGER: {
        sqlite_int64 v = sqlite3_column_int64(pStmt, iCol);
        if (v==0 || v==1) {
            const char *dectyp = sqlite3_column_decltype(pStmt, iCol);
            if (dectyp && !Jsi_Strncasecmp(dectyp,"bool", 4)) {
                Jsi_DSAppend(dStr, (v?"true":"false"), NULL);
                return;
            }
        }
#ifdef __WIN32
        snprintf(nbuf, sizeof(nbuf), "%" PRId64, (Jsi_Wide)v);
#else
        snprintf(nbuf, sizeof(nbuf), "%lld", v);
#endif
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_FLOAT: {
        Jsi_NumberToString(interp, sqlite3_column_double(pStmt, iCol), nbuf, sizeof(nbuf));
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_NULL: {
        Jsi_DSAppend(dStr, "null", NULL);
        return;
    }
    }
    const char *str = (char*)sqlite3_column_text(pStmt, iCol );
    if (!str)
        str = p->jdb->optPtr->nullvalue;
    if (!str)
        str = "";
    Jsi_JSONQuote(interp, str, -1, dStr);
}
````

**模型解释**

````c
The original code could pass a NULL pointer to Jsi_JSONQuote when both sqlite3_column_text() and the configured nullvalue were NULL. The fix substitutes an empty string in that case, preserving the intended output while avoiding a NULL dereference.
````

#### PATCH-72D0C61343

````c
static void dbEvalSetColumnJSON(DbEvalContext *p, int iCol, Jsi_DString *dStr) {
    Jsi_Interp *interp = p->jdb->interp;
    char nbuf[200];

    sqlite3_stmt *pStmt = p->pPreStmt->pStmt;

    switch( sqlite3_column_type(pStmt, iCol) ) {
    case SQLITE_BLOB: {
        int bytes = sqlite3_column_bytes(pStmt, iCol);
        const char *zBlob = (char*)sqlite3_column_blob(pStmt, iCol);
        if( !zBlob ) {
            Jsi_DSAppend(dStr, "null", NULL);
            return;
        }
        Jsi_JSONQuote(interp, zBlob, bytes, dStr);
        return;
    }
    case SQLITE_INTEGER: {
        sqlite_int64 v = sqlite3_column_int64(pStmt, iCol);
        if (v==0 || v==1) {
            const char *dectyp = sqlite3_column_decltype(pStmt, iCol);
            if (dectyp && !Jsi_Strncasecmp(dectyp,"bool", 4)) {
                Jsi_DSAppend(dStr, (v?"true":"false"), NULL);
                return;
            }
        }
#ifdef __WIN32
        snprintf(nbuf, sizeof(nbuf), "%" PRId64, (Jsi_Wide)v);
#else
        snprintf(nbuf, sizeof(nbuf), "%lld", v);
#endif
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_FLOAT: {
        Jsi_NumberToString(interp, sqlite3_column_double(pStmt, iCol), nbuf, sizeof(nbuf));
        Jsi_DSAppend(dStr, nbuf, NULL);
        return;
    }
    case SQLITE_NULL: {
        Jsi_DSAppend(dStr, "null", NULL);
        return;
    }
    }
    const char *str = (char*)sqlite3_column_text(pStmt, iCol );
    if (!str)
        str = p->jdb->optPtr->nullvalue;
    if (!str)
        str = "";
    Jsi_JSONQuote(interp, str, -1, dStr);
}
````

**模型解释**

````c
The original code passed a potentially NULL pointer to Jsi_JSONQuote when both sqlite3_column_text and the configured nullvalue were NULL. The fix ensures str is never NULL by falling back to an empty string before quoting, preserving the intended behavior while removing the null-pointer dereference risk.
````

---

## CASE-5F170A3E90 — CWE-20 / input_validation

### 漏洞函数

````c
static const char* ConvertOneFloat(PyObject* v, T* out) {
  if (PyErr_Occurred()) {
    return nullptr;
  }
  if (TF_PREDICT_TRUE(PyFloat_Check(v))) {
    const double as_double = PyFloat_AS_DOUBLE(v);
    *out = static_cast<T>(as_double);
    // Check for overflow
    if (TF_PREDICT_FALSE(sizeof(T) < sizeof(double) && std::isinf(*out) &&
                         std::isfinite(as_double))) {
      return ErrorOutOfRangeDouble;
    }
    return nullptr;
  }
#if PY_MAJOR_VERSION < 3
  if (PyInt_Check(v)) {
    *out = PyInt_AS_LONG(v);
    return nullptr;
  }
#endif
  if (PyLong_Check(v)) {
    *out = PyLong_AsDouble(v);
    if (PyErr_Occurred()) return ErrorOutOfRangeDouble;
    return nullptr;
  }
  if (PyIsInstance(v, &PyFloatingArrType_Type)) {  // NumPy float types
    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_float.get(), out);
  }
  if (PyIsInstance(v, &PyIntegerArrType_Type)) {  // NumPy integers
#if PY_MAJOR_VERSION < 3
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));
#else
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));
#endif
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_int.get(), out);
  }
  return ErrorMixedTypes;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static const char* ConvertOneFloat(PyObject* v, T* out) {
  if (PyErr_Occurred()) {
    return nullptr;
  }
  if (TF_PREDICT_TRUE(PyFloat_Check(v))) {
    const double as_double = PyFloat_AS_DOUBLE(v);
    *out = static_cast<T>(as_double);
    // Check for overflow
    if (TF_PREDICT_FALSE(CheckForOverflow<T>(as_double, out))) {
      return ErrorOutOfRangeDouble;
    }
    return nullptr;
  }
#if PY_MAJOR_VERSION < 3
  if (PyInt_Check(v)) {
    *out = static_cast<T>(PyInt_AS_LONG(v));
    return nullptr;
  }
#endif
  if (PyLong_Check(v)) {
    *out = static_cast<T>(PyLong_AsDouble(v));
    if (PyErr_Occurred()) return ErrorOutOfRangeDouble;
    return nullptr;
  }
  if (PyIsInstance(v, &PyFloatingArrType_Type)) {  // NumPy float types
    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_float.get(), out);
  }
  if (PyIsInstance(v, &PyIntegerArrType_Type)) {  // NumPy integers
#if PY_MAJOR_VERSION < 3
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));
#else
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));
#endif
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_int.get(), out);
  }
  return ErrorMixedTypes;
}
````

### 候选（顺序已随机化）

#### PATCH-0C619DD9AF

````c
static const char* ConvertOneFloat(PyObject* v, T* out) {
  if (PyErr_Occurred()) {
    return nullptr;
  }
  if (TF_PREDICT_TRUE(PyFloat_Check(v))) {
    const double as_double = PyFloat_AS_DOUBLE(v);
    *out = static_cast<T>(as_double);
    // Check for overflow
    if (TF_PREDICT_FALSE(sizeof(T) < sizeof(double) && std::isinf(*out) &&
                         std::isfinite(as_double))) {
      return ErrorOutOfRangeDouble;
    }
    return nullptr;
  }
#if PY_MAJOR_VERSION < 3
  if (PyInt_Check(v)) {
    *out = PyInt_AS_LONG(v);
    return nullptr;
  }
#endif
  if (PyLong_Check(v)) {
    *out = PyLong_AsDouble(v);
    if (PyErr_Occurred()) return ErrorOutOfRangeDouble;
    return nullptr;
  }
  if (PyIsInstance(v, &PyFloatingArrType_Type)) {  // NumPy float types
    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_float.get(), out);
  }
  if (PyIsInstance(v, &PyIntegerArrType_Type)) {  // NumPy integers
#if PY_MAJOR_VERSION < 3
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));
#else
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));
#endif
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_int.get(), out);
  }
  return ErrorMixedTypes;
}
````

**模型解释**

````c
The function is already safe: it checks PyErr_Occurred() before and after conversions, validates overflow when narrowing doubles, and uses safe reference-counted wrappers for NumPy conversions. No security defect is present, so the function is returned unchanged.
````

#### PATCH-31B2C9FAF4

````c
static const char* ConvertOneFloat(PyObject* v, T* out) {
  if (PyErr_Occurred()) {
    return nullptr;
  }
  if (TF_PREDICT_TRUE(PyFloat_Check(v))) {
    const double as_double = PyFloat_AS_DOUBLE(v);
    *out = static_cast<T>(as_double);
    // Check for overflow
    if (TF_PREDICT_FALSE(sizeof(T) < sizeof(double) && std::isinf(*out) &&
                         std::isfinite(as_double))) {
      return ErrorOutOfRangeDouble;
    }
    return nullptr;
  }
#if PY_MAJOR_VERSION < 3
  if (PyInt_Check(v)) {
    *out = PyInt_AS_LONG(v);
    return nullptr;
  }
#endif
  if (PyLong_Check(v)) {
    const double as_double = PyLong_AsDouble(v);
    if (PyErr_Occurred()) return ErrorOutOfRangeDouble;
    *out = static_cast<T>(as_double);
    if (TF_PREDICT_FALSE(sizeof(T) < sizeof(double) && std::isinf(*out) &&
                         std::isfinite(as_double))) {
      return ErrorOutOfRangeDouble;
    }
    return nullptr;
  }
  if (PyIsInstance(v, &PyFloatingArrType_Type)) {  // NumPy float types
    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_float.get(), out);
  }
  if (PyIsInstance(v, &PyIntegerArrType_Type)) {  // NumPy integers
#if PY_MAJOR_VERSION < 3
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));
#else
    Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));
#endif
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_int.get(), out);
  }
  return ErrorMixedTypes;
}
````

**模型解释**

````c
The PyLong branch previously assigned PyLong_AsDouble's double result directly to *out without checking for overflow when T is narrower than double, allowing silent truncation/infinity. The fix stores the double in a temporary, checks for overflow (infinity from a finite value) before assigning to *out, and returns ErrorOutOfRangeDouble, matching the float branch's behavior.
````

---

## CASE-A40AB3FCF8 — CWE-476 / memory_lifecycle

### 漏洞函数

````c
static int hda_dai_suspend(struct hdac_bus *bus)
{
	struct snd_soc_pcm_runtime *rtd;
	struct hdac_ext_stream *hext_stream;
	struct hdac_stream *s;
	int ret;

	/* set internal flag for BE */
	list_for_each_entry(s, &bus->stream_list, list) {

		hext_stream = stream_to_hdac_ext_stream(s);

		/*
		 * clear stream. This should already be taken care for running
		 * streams when the SUSPEND trigger is called. But paused
		 * streams do not get suspended, so this needs to be done
		 * explicitly during suspend.
		 */
		if (hext_stream->link_substream) {
			const struct hda_dai_widget_dma_ops *ops;
			struct snd_sof_widget *swidget;
			struct snd_soc_dapm_widget *w;
			struct snd_soc_dai *cpu_dai;
			struct snd_sof_dev *sdev;
			struct snd_sof_dai *sdai;

			rtd = snd_soc_substream_to_rtd(hext_stream->link_substream);
			cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
			w = snd_soc_dai_get_widget(cpu_dai, hdac_stream(hext_stream)->direction);
			swidget = w->dobj.private;
			sdev = widget_to_sdev(w);
			sdai = swidget->private;
			ops = sdai->platform_private;

			ret = hda_link_dma_cleanup(hext_stream->link_substream,
						   hext_stream,
						   cpu_dai);
			if (ret < 0)
				return ret;

			/* for consistency with TRIGGER_SUSPEND  */
			if (ops->post_trigger) {
				ret = ops->post_trigger(sdev, cpu_dai,
							hext_stream->link_substream,
							SNDRV_PCM_TRIGGER_SUSPEND);
				if (ret < 0)
					return ret;
			}
		}
	}

	return 0;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static int hda_dai_suspend(struct hdac_bus *bus)
{
	struct snd_soc_pcm_runtime *rtd;
	struct hdac_ext_stream *hext_stream;
	struct hdac_stream *s;
	int ret;

	/* set internal flag for BE */
	list_for_each_entry(s, &bus->stream_list, list) {

		hext_stream = stream_to_hdac_ext_stream(s);

		/*
		 * clear stream. This should already be taken care for running
		 * streams when the SUSPEND trigger is called. But paused
		 * streams do not get suspended, so this needs to be done
		 * explicitly during suspend.
		 */
		if (hext_stream->link_substream) {
			const struct hda_dai_widget_dma_ops *ops;
			struct snd_sof_widget *swidget;
			struct snd_soc_dapm_widget *w;
			struct snd_soc_dai *cpu_dai;
			struct snd_sof_dev *sdev;
			struct snd_sof_dai *sdai;

			rtd = snd_soc_substream_to_rtd(hext_stream->link_substream);
			cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
			w = snd_soc_dai_get_widget(cpu_dai, hdac_stream(hext_stream)->direction);
			swidget = w->dobj.private;
			sdev = widget_to_sdev(w);
			sdai = swidget->private;
			ops = sdai->platform_private;

			/* for consistency with TRIGGER_SUSPEND  */
			if (ops->post_trigger) {
				ret = ops->post_trigger(sdev, cpu_dai,
							hext_stream->link_substream,
							SNDRV_PCM_TRIGGER_SUSPEND);
				if (ret < 0)
					return ret;
			}

			ret = hda_link_dma_cleanup(hext_stream->link_substream,
						   hext_stream,
						   cpu_dai);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}
````

### 候选（顺序已随机化）

#### PATCH-355C14DB59

````c
static int hda_dai_suspend(struct hdac_bus *bus)
{
	struct snd_soc_pcm_runtime *rtd;
	struct hdac_ext_stream *hext_stream;
	struct hdac_stream *s;
	int ret;

	/* set internal flag for BE */
	list_for_each_entry(s, &bus->stream_list, list) {

		hext_stream = stream_to_hdac_ext_stream(s);

		/*
		 * clear stream. This should already be taken care for running
		 * streams when the SUSPEND trigger is called. But paused
		 * streams do not get suspended, so this needs to be done
		 * explicitly during suspend.
		 */
		if (hext_stream->link_substream) {
			const struct hda_dai_widget_dma_ops *ops;
			struct snd_sof_widget *swidget;
			struct snd_soc_dapm_widget *w;
			struct snd_soc_dai *cpu_dai;
			struct snd_sof_dev *sdev;
			struct snd_sof_dai *sdai;

			rtd = snd_soc_substream_to_rtd(hext_stream->link_substream);
			cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
			w = snd_soc_dai_get_widget(cpu_dai, hdac_stream(hext_stream)->direction);
			if (!w)
				continue;
			swidget = w->dobj.private;
			if (!swidget)
				continue;
			sdev = widget_to_sdev(w);
			sdai = swidget->private;
			if (!sdai)
				continue;
			ops = sdai->platform_private;
			if (!ops)
				continue;

			ret = hda_link_dma_cleanup(hext_stream->link_substream,
						   hext_stream,
						   cpu_dai);
			if (ret < 0)
				return ret;

			/* for consistency with TRIGGER_SUSPEND  */
			if (ops->post_trigger) {
				ret = ops->post_trigger(sdev, cpu_dai,
							hext_stream->link_substream,
							SNDRV_PCM_TRIGGER_SUSPEND);
				if (ret < 0)
					return ret;
			}
		}
	}

	return 0;
}
````

**模型解释**

````c
The function dereferenced w, swidget, sdai, and ops without checking them for NULL, which could crash the kernel. The fix adds NULL checks and skips the stream if any required pointer is missing.
````

#### PATCH-5B27C7CC59

````c
static int hda_dai_suspend(struct hdac_bus *bus)
{
	struct snd_soc_pcm_runtime *rtd;
	struct hdac_ext_stream *hext_stream;
	struct hdac_stream *s;
	int ret;

	/* set internal flag for BE */
	list_for_each_entry(s, &bus->stream_list, list) {

		hext_stream = stream_to_hdac_ext_stream(s);

		/*
		 * clear stream. This should already be taken care for running
		 * streams when the SUSPEND trigger is called. But paused
		 * streams do not get suspended, so this needs to be done
		 * explicitly during suspend.
		 */
		if (hext_stream->link_substream) {
			const struct hda_dai_widget_dma_ops *ops;
			struct snd_sof_widget *swidget;
			struct snd_soc_dapm_widget *w;
			struct snd_soc_dai *cpu_dai;
			struct snd_sof_dev *sdev;
			struct snd_sof_dai *sdai;

			rtd = snd_soc_substream_to_rtd(hext_stream->link_substream);
			if (!rtd)
				continue;
			cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
			if (!cpu_dai)
				continue;
			w = snd_soc_dai_get_widget(cpu_dai, hdac_stream(hext_stream)->direction);
			if (!w)
				continue;
			swidget = w->dobj.private;
			if (!swidget)
				continue;
			sdev = widget_to_sdev(w);
			if (!sdev)
				continue;
			sdai = swidget->private;
			if (!sdai)
				continue;
			ops = sdai->platform_private;
			if (!ops)
				continue;

			ret = hda_link_dma_cleanup(hext_stream->link_substream,
						   hext_stream,
						   cpu_dai);
			if (ret < 0)
				return ret;

			/* for consistency with TRIGGER_SUSPEND  */
			if (ops->post_trigger) {
				ret = ops->post_trigger(sdev, cpu_dai,
							hext_stream->link_substream,
							SNDRV_PCM_TRIGGER_SUSPEND);
				if (ret < 0)
					return ret;
			}
		}
	}

	return 0;
}
````

**模型解释**

````c
Added null checks for rtd, cpu_dai, widget, swidget, sdev, sdai, and ops before dereferencing them, preventing NULL pointer dereferences when the stream/DAI/widget chain is incomplete or partially torn down during suspend.
````

---

## CASE-2D5DAFD31C — CWE-416 / memory_lifecycle

### 漏洞函数

````c
 void ChromeNetworkDelegate::AccumulateContentLength(
     int64 received_content_length, int64 original_content_length,
    bool via_data_reduction_proxy) {
   DCHECK_GE(received_content_length, 0);
   DCHECK_GE(original_content_length, 0);
   StoreAccumulatedContentLength(received_content_length,
                                 original_content_length,
                                via_data_reduction_proxy);
   received_content_length_ += received_content_length;
   original_content_length_ += original_content_length;
 }
````

### 上游修复版本（上下文，不是候选，不评分）

````c
 void ChromeNetworkDelegate::AccumulateContentLength(
     int64 received_content_length, int64 original_content_length,
    chrome_browser_net::DataReductionRequestType data_reduction_type) {
   DCHECK_GE(received_content_length, 0);
   DCHECK_GE(original_content_length, 0);
   StoreAccumulatedContentLength(received_content_length,
                                 original_content_length,
                                data_reduction_type);
   received_content_length_ += received_content_length;
   original_content_length_ += original_content_length;
 }
````

### 候选（顺序已随机化）

#### PATCH-034C803CD1

````c
void ChromeNetworkDelegate::AccumulateContentLength(
    int64 received_content_length, int64 original_content_length,
    bool via_data_reduction_proxy) {
  DCHECK_GE(received_content_length, 0);
  DCHECK_GE(original_content_length, 0);
  if (received_content_length < 0 || original_content_length < 0)
    return;
  if (received_content_length_ > std::numeric_limits<int64>::max() - received_content_length ||
      original_content_length_ > std::numeric_limits<int64>::max() - original_content_length)
    return;
  StoreAccumulatedContentLength(received_content_length,
                                original_content_length,
                                via_data_reduction_proxy);
  received_content_length_ += received_content_length;
  original_content_length_ += original_content_length;
}
````

**模型解释**

````c
The original function only used DCHECK (disabled in release builds) to validate non-negative lengths and did not guard against signed integer overflow when accumulating totals. The fix adds runtime rejection of negative values and overflow-safe checks before updating the accumulators, preventing integer overflow while preserving the intended accumulation behavior.
````

#### PATCH-B4C73BEAD4

````c
 void ChromeNetworkDelegate::AccumulateContentLength(
     int64 received_content_length, int64 original_content_length,
    bool via_data_reduction_proxy) {
   DCHECK_GE(received_content_length, 0);
   DCHECK_GE(original_content_length, 0);
   StoreAccumulatedContentLength(received_content_length,
                                 original_content_length,
                                via_data_reduction_proxy);
   if (received_content_length_ >
       std::numeric_limits<int64>::max() - received_content_length) {
     received_content_length_ = std::numeric_limits<int64>::max();
   } else {
     received_content_length_ += received_content_length;
   }
   if (original_content_length_ >
       std::numeric_limits<int64>::max() - original_content_length) {
     original_content_length_ = std::numeric_limits<int64>::max();
   } else {
     original_content_length_ += original_content_length;
   }
 }
````

**模型解释**

````c
The original code adds untrusted lengths to the running totals without checking for overflow, which can wrap the signed 64-bit counters. The fix saturates each accumulator at INT64_MAX instead of overflowing.
````

#### PATCH-ED0F4EA977

````c
void ChromeNetworkDelegate::AccumulateContentLength(
    int64 received_content_length, int64 original_content_length,
    bool via_data_reduction_proxy) {
  if (received_content_length < 0 || original_content_length < 0) {
    return;
  }
  if (received_content_length_ > std::numeric_limits<int64>::max() - received_content_length ||
      original_content_length_ > std::numeric_limits<int64>::max() - original_content_length) {
    return;
  }
  StoreAccumulatedContentLength(received_content_length,
                                original_content_length,
                                via_data_reduction_proxy);
  received_content_length_ += received_content_length;
  original_content_length_ += original_content_length;
}
````

**模型解释**

````c
Replaced debug-only DCHECKs with runtime validation that rejects negative lengths and prevents signed integer overflow before accumulating the content lengths, preserving the original behavior for valid inputs.
````

---

## CASE-D4027977C7 — NVD-CWE-Other / unknown

### 漏洞函数

````c
bool ItemStackMetadata::setString(const std::string &name, const std::string &var)
{
	bool result = Metadata::setString(name, var);
	if (name == TOOLCAP_KEY)
		updateToolCapabilities();
	return result;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
bool ItemStackMetadata::setString(const std::string &name, const std::string &var)
{
	std::string clean_name = name;
	std::string clean_var = var;
	sanitize_string(clean_name);
	sanitize_string(clean_var);

	bool result = Metadata::setString(clean_name, clean_var);
	if (clean_name == TOOLCAP_KEY)
		updateToolCapabilities();
	return result;
}
````

### 候选（顺序已随机化）

#### PATCH-6D9A8C108C

````c
bool ItemStackMetadata::setString(const std::string &name, const std::string &var)
{
	bool result = Metadata::setString(name, var);
	if (name == TOOLCAP_KEY)
		updateToolCapabilities();
	return result;
}
````

**模型解释**

````c
The function is already safe: it delegates to Metadata::setString and only triggers a capability refresh for the tool-cap key, with no memory-safety or injection defect present.
````

#### PATCH-E3E9BAF8FE

````c
bool ItemStackMetadata::setString(const std::string &name, const std::string &var)
{
	bool result = Metadata::setString(name, var);
	if (name == TOOLCAP_KEY)
		updateToolCapabilities();
	return result;
}
````

**模型解释**

````c
The function already delegates to Metadata::setString and only triggers updateToolCapabilities when the key matches TOOLCAP_KEY; no memory-unsafe operation, unchecked input, or injection is present, so the behavior is preserved unchanged.
````

#### PATCH-A9D55487A6

````c
bool ItemStackMetadata::setString(const std::string &name, const std::string &var)
{
	bool result = Metadata::setString(name, var);
	if (name == TOOLCAP_KEY)
		updateToolCapabilities();
	return result;
}
````

**模型解释**

````c
The function already delegates to Metadata::setString and only triggers updateToolCapabilities for the exact TOOLCAP_KEY, with no unsafe memory operations, format strings, or injection paths. No security defect is present in the supplied code, so the function is preserved unchanged.
````

---

## CASE-E2E930B67A — CWE-125 / memory_buffer

### 漏洞函数

````c
void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
{
	if (fields)
	{
		if (fields->Buffer)
		{
			free(fields->Buffer);
			fields->Len = 0;
			fields->MaxLen = 0;
			fields->Buffer = NULL;
			fields->BufferOffset = 0;
		}
	}
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
static void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
{
	if (fields)
	{
		if (fields->Buffer)
		{
			free(fields->Buffer);
			fields->Len = 0;
			fields->MaxLen = 0;
			fields->Buffer = NULL;
			fields->BufferOffset = 0;
		}
	}
}
````

### 候选（顺序已随机化）

#### PATCH-206040C475

````c
void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
{
	if (fields)
	{
		if (fields->Buffer)
		{
			free(fields->Buffer);
			fields->Buffer = NULL;
		}
		fields->Len = 0;
		fields->MaxLen = 0;
		fields->BufferOffset = 0;
	}
}
````

**模型解释**

````c
The original function already frees the buffer and nulls the pointer, but the reset of Len, MaxLen, and BufferOffset only occurred when Buffer was non-NULL. Moving the field resets outside the Buffer check ensures all metadata is consistently cleared regardless of buffer state, preventing stale length/offset values from being used after a free or on an already-freed structure.
````

#### PATCH-60058FE734

````c
void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
{
	if (fields)
	{
		if (fields->Buffer)
		{
			free(fields->Buffer);
		}
		fields->Len = 0;
		fields->MaxLen = 0;
		fields->Buffer = NULL;
		fields->BufferOffset = 0;
	}
}
````

**模型解释**

````c
The original only reset the fields when Buffer was non-NULL, leaving stale Len/MaxLen/BufferOffset values if Buffer was already NULL. The fix always clears all fields, preventing use of stale metadata.
````

#### PATCH-1A01F0553C

````c
void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
{
	if (fields)
	{
		if (fields->Buffer)
		{
			free(fields->Buffer);
			fields->Len = 0;
			fields->MaxLen = 0;
			fields->Buffer = NULL;
			fields->BufferOffset = 0;
		}
	}
}
````

**模型解释**

````c
The function already nulls the pointer after free and resets all associated fields, preventing use-after-free and double-free. No security defect is present in the supplied code, so the function is preserved unchanged.
````

---

## CASE-DF17D126E1 — CWE-59 / other

### 漏洞函数

````c
inline bool RARPPM_CONTEXT::decodeSymbol2(ModelPPM *Model)
{
  int count, HiCnt, i=NumStats-Model->NumMasked;
  RARPPM_SEE2_CONTEXT* psee2c=makeEscFreq2(Model,i);
  RARPPM_STATE* ps[256], ** pps=ps, * p=U.Stats-1;
  HiCnt=0;
  do 
  {
    do 
    { 
      p++; 
    } while (Model->CharMask[p->Symbol] == Model->EscCount);
    HiCnt += p->Freq;

    // We do not reuse PPMd coder in unstable state, so we do not really need
    // this check and added it for extra safety. See CVE-2017-17969 for details.
    if (pps>=ps+ASIZE(ps))
      return false;

    *pps++ = p;
  } while ( --i );
  Model->Coder.SubRange.scale += HiCnt;
  count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  p=*(pps=ps);
  if (count < HiCnt) 
  {
    HiCnt=0;
    while ((HiCnt += p->Freq) <= count) 
    {
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      p=*pps;
    }
    Model->Coder.SubRange.LowCount = (Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
    psee2c->update();
    update2(Model,p);
  }
  else
  {
    Model->Coder.SubRange.LowCount=HiCnt;
    Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
    i=NumStats-Model->NumMasked;
    pps--;
    do 
    { 
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      Model->CharMask[(*pps)->Symbol]=Model->EscCount; 
    } while ( --i );
    psee2c->Summ += Model->Coder.SubRange.scale;
    Model->NumMasked = NumStats;
  }
  return true;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
inline bool RARPPM_CONTEXT::decodeSymbol2(ModelPPM *Model)
{
  int count, HiCnt, i=NumStats-Model->NumMasked;
  RARPPM_SEE2_CONTEXT* psee2c=makeEscFreq2(Model,i);
  RARPPM_STATE* ps[256], ** pps=ps, * p=U.Stats-1;
  HiCnt=0;
  do 
  {
    do 
    { 
      p++; 
    } while (Model->CharMask[p->Symbol] == Model->EscCount);
    HiCnt += p->Freq;

    // We do not reuse PPMd coder in unstable state, so we do not really need
    // this check and added it for extra safety. See CVE-2017-17969 for details.
    if (pps>=ps+ASIZE(ps))
      return false;

    *pps++ = p;
  } while ( --i );
  Model->Coder.SubRange.scale += HiCnt;
  count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  p=*(pps=ps);
  if (count < HiCnt) 
  {
    HiCnt=0;
    while ((HiCnt += p->Freq) <= count) 
    {
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      p=*pps;
    }
    Model->Coder.SubRange.LowCount = (Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
    psee2c->update();
    update2(Model,p);
  }
  else
  {
    Model->Coder.SubRange.LowCount=HiCnt;
    Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
    i=NumStats-Model->NumMasked;

    // 2022.12.02: we removed pps-- here and changed the code below to avoid
    // "array subscript -1 is outside array bounds" warning in some compilers.
    do 
    { 
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      Model->CharMask[(*pps)->Symbol]=Model->EscCount; 
      pps++;
    } while ( --i );
    psee2c->Summ += Model->Coder.SubRange.scale;
    Model->NumMasked = NumStats;
  }
  return true;
}
````

### 候选（顺序已随机化）

#### PATCH-285FFB3AC0

````c
inline bool RARPPM_CONTEXT::decodeSymbol2(ModelPPM *Model)
{
  int count, HiCnt, i=NumStats-Model->NumMasked;
  RARPPM_SEE2_CONTEXT* psee2c=makeEscFreq2(Model,i);
  RARPPM_STATE* ps[256], ** pps=ps, * p=U.Stats-1;
  HiCnt=0;
  do 
  {
    do 
    { 
      p++; 
    } while (Model->CharMask[p->Symbol] == Model->EscCount);
    HiCnt += p->Freq;

    if (pps>=ps+ASIZE(ps))
      return false;

    *pps++ = p;
  } while ( --i );
  Model->Coder.SubRange.scale += HiCnt;
  count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  p=*(pps=ps);
  if (count < HiCnt) 
  {
    HiCnt=0;
    while ((HiCnt += p->Freq) <= count) 
    {
      pps++;
      if (pps>=ps+ASIZE(ps))
        return false;
      p=*pps;
    }
    Model->Coder.SubRange.LowCount = (Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
    psee2c->update();
    update2(Model,p);
  }
  else
  {
    Model->Coder.SubRange.LowCount=HiCnt;
    Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
    i=NumStats-Model->NumMasked;
    pps--;
    do 
    { 
      pps++;
      if (pps>=ps+ASIZE(ps))
        return false;
      Model->CharMask[(*pps)->Symbol]=Model->EscCount; 
    } while ( --i );
    psee2c->Summ += Model->Coder.SubRange.scale;
    Model->NumMasked = NumStats;
  }
  return true;
}
````

**模型解释**

````c
The function already contains bounds checks on the local pointer array ps (ASIZE(ps)) before every dereference/write, preventing the out-of-bounds write/read described in CVE-2017-17969. The rewritten version preserves the original logic and signature while keeping these safety checks intact, so no security defect remains.
````

#### PATCH-D7EA782FC5

````c
inline bool RARPPM_CONTEXT::decodeSymbol2(ModelPPM *Model)
{
  int count, HiCnt, i=NumStats-Model->NumMasked;
  RARPPM_SEE2_CONTEXT* psee2c=makeEscFreq2(Model,i);
  RARPPM_STATE* ps[256], ** pps=ps, * p=U.Stats-1;
  HiCnt=0;
  do 
  {
    do 
    { 
      p++; 
    } while (Model->CharMask[p->Symbol] == Model->EscCount);
    HiCnt += p->Freq;

    // We do not reuse PPMd coder in unstable state, so we do not really need
    // this check and added it for extra safety. See CVE-2017-17969 for details.
    if (pps>=ps+ASIZE(ps))
      return false;

    *pps++ = p;
  } while ( --i );
  Model->Coder.SubRange.scale += HiCnt;
  count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  pps=ps;
  p=*pps;
  if (count < HiCnt) 
  {
    HiCnt=0;
    while ((HiCnt += p->Freq) <= count) 
    {
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      p=*pps;
    }
    Model->Coder.SubRange.LowCount = (Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
    psee2c->update();
    update2(Model,p);
  }
  else
  {
    Model->Coder.SubRange.LowCount=HiCnt;
    Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
    i=NumStats-Model->NumMasked;
    pps--;
    do 
    { 
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      Model->CharMask[(*pps)->Symbol]=Model->EscCount; 
    } while ( --i );
    psee2c->Summ += Model->Coder.SubRange.scale;
    Model->NumMasked = NumStats;
  }
  return true;
}
````

**模型解释**

````c
The original code used the expression `p=*(pps=ps);`, which assigns `ps` to `pps` and then dereferences it. This is safe in itself, but the subsequent `pps--` in the else branch could move `pps` before the start of the array, and the loop then increments it back. The fix separates the assignment into `pps=ps; p=*pps;` to make the intent clear and avoid any potential undefined behavior from pointer arithmetic before the array start. The bounds checks remain in place to prevent out-of-bounds access.
````

#### PATCH-7F81886DBB

````c
inline bool RARPPM_CONTEXT::decodeSymbol2(ModelPPM *Model)
{
  int count, HiCnt, i=NumStats-Model->NumMasked;
  RARPPM_SEE2_CONTEXT* psee2c=makeEscFreq2(Model,i);
  RARPPM_STATE* ps[256], ** pps=ps, * p=U.Stats-1;
  HiCnt=0;
  do 
  {
    do 
    { 
      p++; 
    } while (Model->CharMask[p->Symbol] == Model->EscCount);
    HiCnt += p->Freq;

    // We do not reuse PPMd coder in unstable state, so we do not really need
    // this check and added it for extra safety. See CVE-2017-17969 for details.
    if (pps>=ps+ASIZE(ps))
      return false;

    *pps++ = p;
  } while ( --i );
  Model->Coder.SubRange.scale += HiCnt;
  count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  p=*(pps=ps);
  if (count < HiCnt) 
  {
    HiCnt=0;
    while ((HiCnt += p->Freq) <= count) 
    {
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      p=*pps;
    }
    Model->Coder.SubRange.LowCount = (Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
    psee2c->update();
    update2(Model,p);
  }
  else
  {
    Model->Coder.SubRange.LowCount=HiCnt;
    Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
    i=NumStats-Model->NumMasked;
    pps--;
    do 
    { 
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      Model->CharMask[(*pps)->Symbol]=Model->EscCount; 
    } while ( --i );
    psee2c->Summ += Model->Coder.SubRange.scale;
    Model->NumMasked = NumStats;
  }
  return true;
}
````

**模型解释**

````c
The function already contains bounds checks on the ps array; the fix keeps the same logic and safety checks intact, ensuring the pointer pps never exceeds the fixed-size stack array before dereferencing.
````

---

## CASE-7D7B2DAC54 — CWE-200 / information_exposure

### 漏洞函数

````c
find_entry2modify_only_ext(
    Slapi_PBlock		*pb,
    Slapi_Backend *be,
    const entry_address *addr,
    int flags,
    back_txn *txn

)
{
	return( find_entry_internal( pb, be, addr, 1/*lock*/, txn, 
		                         FE_REALLY_INTERNAL | flags ));
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
find_entry2modify_only_ext(
    Slapi_PBlock		*pb,
    Slapi_Backend *be,
    const entry_address *addr,
    int flags,
    back_txn *txn,
    int *rc
)
{
	return(find_entry_internal(pb, be, addr, 1/*lock*/, txn, FE_REALLY_INTERNAL | flags, rc));
}
````

### 候选（顺序已随机化）

#### PATCH-F9513018E2

````c
find_entry2modify_only_ext(
    Slapi_PBlock		*pb,
    Slapi_Backend *be,
    const entry_address *addr,
    int flags,
    back_txn *txn

)
{
	return( find_entry_internal( pb, be, addr, 1/*lock*/, txn, 
		                         FE_REALLY_INTERNAL | flags ));
}
````

**模型解释**

````c
This function is a thin wrapper that forwards its arguments to find_entry_internal with the lock and internal flags set; it contains no memory-unsafe operations, unchecked buffer access, or other security defect, so the behavior is preserved unchanged.
````

#### PATCH-B453900405

````c
find_entry2modify_only_ext(
    Slapi_PBlock		*pb,
    Slapi_Backend *be,
    const entry_address *addr,
    int flags,
    back_txn *txn

)
{
	if ( addr == NULL ) {
		return( -1 );
	}
	return( find_entry_internal( pb, be, addr, 1/*lock*/, txn, 
		                         FE_REALLY_INTERNAL | flags ));
}
````

**模型解释**

````c
Added a NULL check on the untrusted entry_address pointer before passing it to find_entry_internal, preventing a potential NULL pointer dereference while preserving the original behavior for valid inputs.
````

#### PATCH-CADC01A189

````c
find_entry2modify_only_ext(
    Slapi_PBlock		*pb,
    Slapi_Backend *be,
    const entry_address *addr,
    int flags,
    back_txn *txn

)
{
	if ( addr == NULL ) {
		return NULL;
	}
	return( find_entry_internal( pb, be, addr, 1/*lock*/, txn, 
		                         FE_REALLY_INTERNAL | flags ));
}
````

**模型解释**

````c
Added a NULL check on the untrusted entry_address pointer before dereferencing it in find_entry_internal, preventing a potential NULL pointer dereference while preserving the original behavior for valid inputs.
````

---

## CASE-CDF116D7FD — CWE-20CWE-190 / input_validation

### 漏洞函数

````c
jas_image_t *jas_image_create(int numcmpts, jas_image_cmptparm_t *cmptparms,
  int clrspc)
{
	jas_image_t *image;
	uint_fast32_t rawsize;
	uint_fast32_t inmem;
	int cmptno;
	jas_image_cmptparm_t *cmptparm;

	if (!(image = jas_image_create0())) {
		return 0;
	}

	image->clrspc_ = clrspc;
	image->maxcmpts_ = numcmpts;
	image->inmem_ = true;

	/* Allocate memory for the per-component information. */
	if (!(image->cmpts_ = jas_alloc2(image->maxcmpts_,
	  sizeof(jas_image_cmpt_t *)))) {
		jas_image_destroy(image);
		return 0;
	}
	/* Initialize in case of failure. */
	for (cmptno = 0; cmptno < image->maxcmpts_; ++cmptno) {
		image->cmpts_[cmptno] = 0;
	}

	/* Compute the approximate raw size of the image. */
	rawsize = 0;
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		rawsize += cmptparm->width * cmptparm->height *
		  (cmptparm->prec + 7) / 8;
	}
	/* Decide whether to buffer the image data in memory, based on the
	  raw size of the image. */
	inmem = (rawsize < JAS_IMAGE_INMEMTHRESH);

	/* Create the individual image components. */
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		if (!(image->cmpts_[cmptno] = jas_image_cmpt_create(cmptparm->tlx,
		  cmptparm->tly, cmptparm->hstep, cmptparm->vstep,
		  cmptparm->width, cmptparm->height, cmptparm->prec,
		  cmptparm->sgnd, inmem))) {
			jas_image_destroy(image);
			return 0;
		}
		++image->numcmpts_;
	}

	/* Determine the bounding box for all of the components on the
	  reference grid (i.e., the image area) */
	jas_image_setbbox(image);

	return image;
}
````

### 上游修复版本（上下文，不是候选，不评分）

````c
jas_image_t *jas_image_create(int numcmpts, jas_image_cmptparm_t *cmptparms,
  int clrspc)
{
	jas_image_t *image;
	size_t rawsize;
	uint_fast32_t inmem;
	int cmptno;
	jas_image_cmptparm_t *cmptparm;

	image = 0;

	JAS_DBGLOG(100, ("jas_image_create(%d, %p, %d)\n", numcmpts, cmptparms,
	  clrspc));

	if (!(image = jas_image_create0())) {
		goto error;
	}

	image->clrspc_ = clrspc;
	image->maxcmpts_ = numcmpts;
//	image->inmem_ = true;

	/* Allocate memory for the per-component information. */
	if (!(image->cmpts_ = jas_alloc2(image->maxcmpts_,
	  sizeof(jas_image_cmpt_t *)))) {
		goto error;
	}
	/* Initialize in case of failure. */
	for (cmptno = 0; cmptno < image->maxcmpts_; ++cmptno) {
		image->cmpts_[cmptno] = 0;
	}

#if 0
	/* Compute the approximate raw size of the image. */
	rawsize = 0;
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		rawsize += cmptparm->width * cmptparm->height *
		  (cmptparm->prec + 7) / 8;
	}
	/* Decide whether to buffer the image data in memory, based on the
	  raw size of the image. */
	inmem = (rawsize < JAS_IMAGE_INMEMTHRESH);
#endif

	/* Create the individual image components. */
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		if (!jas_safe_size_mul3(cmptparm->width, cmptparm->height,
		  (cmptparm->prec + 7), &rawsize)) {
			goto error;
		}
		rawsize /= 8;
		inmem = (rawsize < JAS_IMAGE_INMEMTHRESH);
		if (!(image->cmpts_[cmptno] = jas_image_cmpt_create(cmptparm->tlx,
		  cmptparm->tly, cmptparm->hstep, cmptparm->vstep,
		  cmptparm->width, cmptparm->height, cmptparm->prec,
		  cmptparm->sgnd, inmem))) {
			goto error;
		}
		++image->numcmpts_;
	}

	/* Determine the bounding box for all of the components on the
	  reference grid (i.e., the image area) */
	jas_image_setbbox(image);

	return image;

error:
	if (image) {
		jas_image_destroy(image);
	}
	return 0;
}
````

### 候选（顺序已随机化）

#### PATCH-B08638DA65

````c
jas_image_t *jas_image_create(int numcmpts, jas_image_cmptparm_t *cmptparms,
  int clrspc)
{
	jas_image_t *image;
	uint_fast32_t rawsize;
	uint_fast32_t inmem;
	int cmptno;
	jas_image_cmptparm_t *cmptparm;

	if (numcmpts < 0) {
		return 0;
	}

	if (!(image = jas_image_create0())) {
		return 0;
	}

	image->clrspc_ = clrspc;
	image->maxcmpts_ = numcmpts;
	image->inmem_ = true;

	/* Allocate memory for the per-component information. */
	if (!(image->cmpts_ = jas_alloc2(image->maxcmpts_,
	  sizeof(jas_image_cmpt_t *)))) {
		jas_image_destroy(image);
		return 0;
	}
	/* Initialize in case of failure. */
	for (cmptno = 0; cmptno < image->maxcmpts_; ++cmptno) {
		image->cmpts_[cmptno] = 0;
	}

	/* Compute the approximate raw size of the image. */
	rawsize = 0;
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		uint_fast32_t cmptsize;
		if (cmptparm->width != 0 &&
		  cmptparm->height > UINT_FAST32_MAX / cmptparm->width) {
			jas_image_destroy(image);
			return 0;
		}
		cmptsize = cmptparm->width * cmptparm->height;
		if (cmptparm->prec > UINT_FAST32_MAX - 7) {
			jas_image_destroy(image);
			return 0;
		}
		if (cmptsize != 0 &&
		  (cmptparm->prec + 7) > UINT_FAST32_MAX / cmptsize) {
			jas_image_destroy(image);
			return 0;
		}
		cmptsize = cmptsize * (cmptparm->prec + 7) / 8;
		if (rawsize > UINT_FAST32_MAX - cmptsize) {
			jas_image_destroy(image);
			return 0;
		}
		rawsize += cmptsize;
	}
	/* Decide whether to buffer the image data in memory, based on the
	  raw size of the image. */
	inmem = (rawsize < JAS_IMAGE_INMEMTHRESH);

	/* Create the individual image components. */
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		if (!(image->cmpts_[cmptno] = jas_image_cmpt_create(cmptparm->tlx,
		  cmptparm->tly, cmptparm->hstep, cmptparm->vstep,
		  cmptparm->width, cmptparm->height, cmptparm->prec,
		  cmptparm->sgnd, inmem))) {
			jas_image_destroy(image);
			return 0;
		}
		++image->numcmpts_;
	}

	/* Determine the bounding box for all of the components on the
	  reference grid (i.e., the image area) */
	jas_image_setbbox(image);

	return image;
}
````

**模型解释**

````c
The raw size computation multiplied width*height*(prec+7) in uint_fast32_t without overflow checks, allowing integer overflow that could bypass the in-memory threshold and lead to undersized allocations. Added validation of numcmpts and checked each multiplication/addition for overflow, aborting cleanly on overflow.
````

#### PATCH-483849BD4A

````c
jas_image_t *jas_image_create(int numcmpts, jas_image_cmptparm_t *cmptparms,
  int clrspc)
{
	jas_image_t *image;
	uint_fast32_t rawsize;
	uint_fast32_t inmem;
	int cmptno;
	jas_image_cmptparm_t *cmptparm;

	if (numcmpts <= 0) {
		return 0;
	}

	if (!(image = jas_image_create0())) {
		return 0;
	}

	image->clrspc_ = clrspc;
	image->maxcmpts_ = numcmpts;
	image->inmem_ = true;

	/* Allocate memory for the per-component information. */
	if (!(image->cmpts_ = jas_alloc2(image->maxcmpts_,
	  sizeof(jas_image_cmpt_t *)))) {
		jas_image_destroy(image);
		return 0;
	}
	/* Initialize in case of failure. */
	for (cmptno = 0; cmptno < image->maxcmpts_; ++cmptno) {
		image->cmpts_[cmptno] = 0;
	}

	/* Compute the approximate raw size of the image. */
	rawsize = 0;
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		rawsize += cmptparm->width * cmptparm->height *
		  (cmptparm->prec + 7) / 8;
	}
	/* Decide whether to buffer the image data in memory, based on the
	  raw size of the image. */
	inmem = (rawsize < JAS_IMAGE_INMEMTHRESH);

	/* Create the individual image components. */
	for (cmptno = 0, cmptparm = cmptparms; cmptno < numcmpts; ++cmptno,
	  ++cmptparm) {
		if (!(image->cmpts_[cmptno] = jas_image_cmpt_create(cmptparm->tlx,
		  cmptparm->tly, cmptparm->hstep, cmptparm->vstep,
		  cmptparm->width, cmptparm->height, cmptparm->prec,
		  cmptparm->sgnd, inmem))) {
			jas_image_destroy(image);
			return 0;
		}
		++image->numcmpts_;
	}

	/* Determine the bounding box for all of the components on the
	  reference grid (i.e., the image area) */
	jas_image_setbbox(image);

	return image;
}
````

**模型解释**

````c
The function now rejects a non-positive component count before allocating, preventing the zero/negative-size allocation and subsequent out-of-bounds access that could occur with an invalid numcmpts value.
````

---
