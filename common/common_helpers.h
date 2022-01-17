#ifndef __COMMON_HELPERS_H
#define __COMMON_HELPERS_H

void shift_right_vector(int index, struct rule_vector *vector) {

	__u64 val = 0;
	int target_word = index / 64;
	int target_bit = 63 - (index % 64);
	int i;

	for (i=target_word; i<MAX_RULE_WORD; i++) {
		if (i == target_word) {
			__u64 mask = 0;
			if (target_bit < 63) {
				mask = ((__u64)1 << target_bit) - 1;
			} else {
				mask = (((__u64)1 << 63) - 1) | ((__u64)1 << 63);
			}
			__u64 left_word = vector->word[i] & ~mask;
			__u64 right_word = (vector->word[i] >> 1) & mask;
			val = vector->word[i] % 2;
			vector->word[i] = (left_word | right_word);
		} else {
			__u64 new_word = (vector->word[i] >> 1) | (val << 63);
			val = vector->word[i] % 2;
			vector->word[i] = new_word;
		}
	}

	return;
}

void shift_left_vector(int index, struct rule_vector *vector) {

	__u64 val = 0;
	int target_word = index / 64;
	int target_bit = 63 - (index % 64);
	int i;

	for (i=MAX_RULE_WORD-1; i>=target_word; i--) {
		if (i == target_word) {
			__u64 mask = 0;
			if (target_bit < 63) {
				mask = ((__u64)1 << target_bit) - 1;
			} else {
				mask = (((__u64)1 << 63) - 1) | ((__u64)1 << 63);
			}
			__u64 left_word = vector->word[i] & ~mask & ~((__u64)1 << target_bit);
			__u64 right_word = (vector->word[i] << 1) & mask;
			vector->word[i] = (left_word | (right_word | val));
		} else {
			__u64 new_word = (vector->word[i] << 1) | val;
			val = vector->word[i] >> 63;
			vector->word[i] = new_word;
		}
	}

	return;
}

#endif
