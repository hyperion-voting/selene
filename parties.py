import random, string, hashlib
from group import pars_2048

import threshold_crypto as tc
import gmpy2

from primitives import DSA, ElGamalEncryption, NIZK, ChaumPedersenProof
from exceptions import (
    InvalidSignatureException,
    InvalidProofException,
    InvalidWFNProofException,
)

from subroutines import Mixnet


class Voter:
    def __init__(self, group, id, vote_min, vote_max):
        self.id = id
        self.vote_min = vote_min
        self.vote_max = vote_max
        self.group = group
        self.g_ri = gmpy2.mpz(1)

    def choose_vote_value(self):
        self.vote = random.randrange(self.vote_min, self.vote_max)

    def generate_dsa_keys(self):
        dsa = DSA(self.group)
        self.secret_key, self.public_key = dsa.keygen()

    def generate_trapdoor_keypair(self):
        self.ege = ElGamalEncryption(self.group)
        self.secret_trapdoor_key, self.public_trapdoor_key = self.ege.keygen()

    def generate_pok_trapdoor_keypair(self):
        nizk = NIZK(self.group)
        self.pok_trapdoor_key = nizk.prove(
            self.secret_trapdoor_key, self.public_trapdoor_key, self.id
        )

    def encrypt_vote(self, teller_public_key):
        self.g_vote = self.group.raise_g(int(self.vote))
        self.encrypted_vote = self.ege.encrypt(
            teller_public_key.g_a, self.g_vote
        )

    def generate_wellformedness_proof(self, teller_public_key):
        encrypted_vote = {
            "c1": self.encrypted_vote[0],
            "c2": self.encrypted_vote[1],
        }
        r = self.encrypted_vote[2]
        chmp = ChaumPedersenProof(self.group)
        self.wellformedness_proof = chmp.prove_or_n(
            encrypted_vote,
            r,
            teller_public_key.g_a,
            self.vote_max,
            int(self.vote),
            self.id,
        )

    def sign_ballot(self):
        self.dsa = DSA(self.group)
        hash = self.group.hash_to_mpz(
            str(self.encrypted_vote)
            + str(self.public_trapdoor_key)
            # + str(self.pok_trapdoor_key)
            + str(self.wellformedness_proof)
        )
        self.signature = self.dsa.sign(self.secret_key, hash)
        bb_data = {
            "id": self.id,
            "spk": self.public_key,
            "sig": self.signature,
            # only for poc
            "stk": self.secret_trapdoor_key,
            "ev": self.encrypted_vote,
            "ptk": self.public_trapdoor_key,
            # "pi_1": self.pok_trapdoor_key,
            "pi_2": self.wellformedness_proof,
        }
        return bb_data

    def notify(self, r_i_j):
        self.g_ri = gmpy2.f_mod(gmpy2.mul(self.g_ri, r_i_j), self.group.p)

    def retrieve_tracker(self, beta_term):
        ege = ElGamalEncryption(self.group)
        ciphertext = [self.g_ri, beta_term]
        self.tracker = ege.decrypt(self.secret_trapdoor_key, ciphertext)
        return self.tracker


class Teller:
    def __init__(self, group, secret_key_share, public_key):
        self.group = group
        self.secret_key_share = secret_key_share
        self.public_key = public_key
        self.registry = []
        self.ege = ElGamalEncryption(self.group)

    def generate_threshold_keys(k, num_tellers, tc_key_params):
        thresh_params = tc.ThresholdParameters(k, num_tellers)
        pub_key, key_shares = tc.create_public_key_and_shares_centralized(
            tc_key_params, thresh_params
        )
        return pub_key, key_shares

    def validate_ballot(group, teller_public_key, ballot):
        dsa = DSA(group)
        hash = group.hash_to_mpz(
            str(ballot["ev"])
            + str(ballot["ptk"])
            + str(ballot["pi_1"])
            + str(ballot["pi_2"])
        )
        nizk = NIZK(group)
        chmp = ChaumPedersenProof(group)
        try:
            if not dsa.verify(ballot["spk"], ballot["sig"], hash):
                raise InvalidSignatureException(ballot["id"])
            if not nizk.verify(ballot["pi_1"], ballot["ptk"], ballot["id"]):
                raise InvalidProofException(ballot["id"])
            ciphertext = {"c1": ballot["ev"][0], "c2": ballot["ev"][1]}
            if not chmp.verify_or_n(
                ciphertext,
                teller_public_key.g_a,
                ballot["pi_2"][0],
                ballot["pi_2"][1],
                ballot["pi_2"][2],
                ballot["pi_2"][3],
                ballot["id"],
            ):
                raise InvalidWFNProofException(ballot["id"])
        except Exception as e:
            print(e)

    def ciphertext_list_split(self, list_0, n):
        k, m = divmod(len(list_0), n)
        split_list = [
            list_0[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(n)
        ]
        return split_list

    def tag_ciphertexts(self, list_0):
        list_1 = []
        index = 0
        for item in list_0:
            temp = []
            temp.append(index)
            temp.append(item[0])
            temp.append(item[1])
            list_1.append(temp)
            index = index + 1
        return list_1

    def verify_decryption_proof(
        self,
        tau,
        p_1,
        p_2,
        w,
        public_key_share,
        ciphertexts,
        partial_decryptions,
    ):
        prod_alpha = 1
        prod_partial_decryptions = 1
        alpha_terms = []
        for ciphertext in ciphertexts:
            index = ciphertext[0]
            alpha_terms.append(ciphertext[1][0])
            t = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(
                            str(tau) + str(ciphertext[1][0]) + str(index)
                        ).encode("UTF-8")
                    ).hexdigest()
                ),
                self.group.q,
            )
            s_2 = gmpy2.powmod(ciphertexts[1][0], t, self.group.p)
            prod_alpha = gmpy2.f_mod(gmpy2.mul(prod_alpha, s_2), self.group.p)

        for partial_decryption in partial_decryptions:
            prod_partial_decryptions = self.group.mul_mod_p(
                prod_partial_decryptions, partial_decryption.v_y
            )
        u = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1)
                        + str(p_1)
                        + str(self.group.g)
                        + str(public_key_share)
                        + str(alpha_terms)
                        + str(partial_decryptions)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        v_1 = self.group.mul_mod_p(
            self.group.raise_g(w),
            gmpy2.powmod(public_key_share, u, self.group.p),
        )
        v_2 = gmpy2.powmod(prod_alpha, w, self.group.p)
        v_2 = self.group.mul_mod_p(
            v_2, gmpy2.powmod(prod_partial_decryptions, u, self.group.p)
        )
        if (p_1 == v_1) and (p_2 == v_2):
            return 1
        return 0

    def mp_partial_decrypt_single(self, ciphertexts_in, q1,q2):
        tau = self.group.get_random()
        r = self.group.get_random()
        p_1 = self.group.raise_g(r)
        comm_tau = hashlib.sha256(str(tau).encode("UTF-8")).hexdigest()
        output = []
        proof = []
        prod_alpha = 1
        alpha_terms = []
        index = 0
        for ciphertext in ciphertexts_in:
            alpha = ciphertext['comm']
            t = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau) + str(alpha) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                ),
                self.group.q,
            )
            index = index + 1
            pd = self.ege.partial_decrypt(
                ciphertext['comm'], self.secret_key_share
            )
            prod_alpha = self.group.mul_mod_p(
                prod_alpha, gmpy2.powmod(alpha, t, self.group.p)
            )
            alpha_terms.append(alpha)
            temp = []

            temp.append(index)
            temp.append(pd)

            output.append(temp)
            
        q1.put(output)
        
        p_2 = gmpy2.powmod(prod_alpha, r, self.group.p)
        u = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1)
                        + str(p_2)
                        + str(self.group.g)
                        + str(self.group.raise_g(self.secret_key_share.y))
                        + str(alpha_terms)
                        + str(output)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        w = self.group.sub_mod_q(
            r, self.group.mul_mod_q(u, self.secret_key_share.y)
        )
        q2.put(
            {
                "p_1": p_1,
                "p_2": p_2,
                "w": w,
                "tau": tau,
                
            }
        )

    def mp_partial_decrypt(self, ciphertexts_in, q1, q2, q3):
        tau_1 = self.group.get_random()
        tau_2 = self.group.get_random()
        r_1 = self.group.get_random()
        r_2 = self.group.get_random()
        p_1_1 = self.group.raise_g(r_1)
        p_2_1 = self.group.raise_g(r_2)
        comm_tau_1 = hashlib.sha256(str(tau_1).encode("UTF-8")).hexdigest()
        comm_tau_2 = hashlib.sha256(str(tau_2).encode("UTF-8")).hexdigest()
        output = []
        output2 = []
        proof = []
        prod_alpha_1 = 1
        prod_alpha_2 = 1
        alpha_terms_1 = []
        alpha_terms_2 = []
        for ciphertext in ciphertexts_in:
            index = ciphertext[0]
            alpha_1 = ciphertext[1][0]
            alpha_2 = ciphertext[2][0]
            t_1 = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau_1) + str(alpha_1) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                ),
                self.group.q,
            )
            t_2 = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau_2) + str(alpha_2) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                ),
                self.group.q,
            )
            pd_1 = self.ege.partial_decrypt(
                ciphertext[1], self.secret_key_share
            )
            pd_2 = self.ege.partial_decrypt(
                ciphertext[2], self.secret_key_share
            )
            prod_alpha_1 = self.group.mul_mod_p(
                prod_alpha_1, gmpy2.powmod(alpha_1, t_1, self.group.p)
            )
            prod_alpha_2 = self.group.mul_mod_p(
                prod_alpha_2, gmpy2.powmod(alpha_2, t_2, self.group.p)
            )
            alpha_terms_1.append(alpha_1)
            alpha_terms_2.append(alpha_2)
            temp = []

            temp.append(index)
            temp.append(pd_1)

            output.append(temp)
            temp2 = []
            temp2.append(index)
            temp2.append(pd_2)
            output2.append(temp2)
        q1.put(output)
        q2.put(output2)
        p_1_2 = gmpy2.powmod(prod_alpha_1, r_1, self.group.p)
        p_2_2 = gmpy2.powmod(prod_alpha_2, r_2, self.group.p)
        u_1 = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1_1)
                        + str(p_1_2)
                        + str(self.group.g)
                        + str(self.group.raise_g(self.secret_key_share.y))
                        + str(alpha_terms_1)
                        + str(output)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        u_2 = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_2_1)
                        + str(p_2_2)
                        + str(self.group.g)
                        + str(self.group.raise_g(self.secret_key_share.y))
                        + str(alpha_terms_2)
                        + str(output2)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        w_1 = self.group.sub_mod_q(
            r_1, self.group.mul_mod_q(u_1, self.secret_key_share.y)
        )
        w_2 = self.group.sub_mod_q(
            r_2, self.group.mul_mod_q(u_2, self.secret_key_share.y)
        )
        q3.put(
            {
                "p_1_1": p_1_1,
                "p_1_2": p_1_2,
                "p_2_1": p_2_1,
                "p_2_2": p_2_2,
                "w_1": w_1,
                "w_2": w_2,
                "tau_1": tau_1,
                "tau_2": tau_2,
            }
        )

    def multi_dim_index(self, list, key):
        for item in list:
            if item[0] == key:
                return item
        return None

    def mp_full_decrypt(self, pd1_in, ciphertexts, col, q1):
        result = []
        for item in pd1_in:
            index = item[0]
            ct = self.multi_dim_index(ciphertexts, index)
            ciphertext = tc.EncryptedMessage(ct[col][0], ct[col][1], "")
            result.append(
                [
                    index,
                    self.ege.threshold_decrypt(
                        item[1],
                        ciphertext,
                        tc.ThresholdParameters(2, 3),
                        pars_2048(),
                    ),
                ]
            )
        q1.put(result)
    
    def mp_full_decrypt_single(self, pd1_in, ciphertexts, q1):
        result = []
        for item in pd1_in:
            index = item[0]
            ct = self.multi_dim_index(ciphertexts, index)
            ciphertext = tc.EncryptedMessage(ct[0], ct[1], "")
            result.append(
                [
                    index,
                    self.ege.threshold_decrypt(
                        item[1],
                        ciphertext,
                        tc.ThresholdParameters(2, 3),
                        pars_2048(),
                    ),
                ]
            )
        q1.put(result)


    def full_decrypt(self, pd_in, q1):
        global decrypted
        split_ciphertexts = self.ciphertext_list_split(pd_in, self.core_count)
        processes = [
            multiprocessing.Process(
                target=self.mp_full_decrypt, args=(ciph, q1)
            )
            for ciph in split_ciphertexts
        ]
        for p in processes:
            p.daemon = True
            p.start()
        data = []
        for p in processes:
            data = data + q1.get()

        for p in processes:
            p.join()
            p.close()
        decrypted = data

    def verify_proof_h_r(group, teller_public_key, ballot):
        nizk = NIZK(group)
        try:
            if not nizk.verify_2(
                ballot["h_r"],
                teller_public_key.g_a,
                ballot["ptk"],
                ballot["proof_h_r"],
            ):
                raise InvalidProofException(ballot["id"])
        except Exception as e:
            print(e)

    def re_encryption_mix(self, list_0):
        mx = Mixnet(self.group)
        proof = mx.re_encryption_mix(list_0, self.public_key.g_a)
        return proof

    def verify_re_enc_mix(self, list_0, proof):
        mx = Mixnet(self.group)
        return mx.verify_mix(
            self.public_key.g_a,
            list_0,
            proof[0],
            proof[1],
            proof[2],
            proof[3],
            proof[4],
            proof[5],
            proof[6],
            proof[7],
            proof[8],
            proof[9],
            proof[10],
            proof[11],
            proof[12],
            proof[13],
            proof[14],
            proof[15],
            proof[16],
            proof[17],
            proof[18],
            proof[19],
        )

    def rencryption_mix_trackers(self, encrypted_trackers):
        mx = Mixnet(self.group)
        proof = mx.mix_trackers(encrypted_trackers, self.public_key.g_a)
        list_1 = proof[0]
        mx.verify_mix_trackers(
            self.public_key.g_a,
            encrypted_trackers,
            proof[0],
            proof[1],
            proof[2],
            proof[3],
            proof[4],
            proof[5],
            proof[6],
            proof[7],
            proof[8],
            proof[9],
            proof[10],
            proof[11],
            proof[12],
            proof[13],
            proof[14],
            proof[15],
            proof[16],
        )

        return list_1

    def generate_tracker_commitments(self, tracker_voter_pairs):
        commitments = []
        for tracker_voter_pair in tracker_voter_pairs:
            r_i = self.group.get_random()
            h_ri = gmpy2.powmod(tracker_voter_pair[1], r_i, self.group.p)
            g_ri = self.group.raise_g(r_i)
            ege = ElGamalEncryption(self.group)
            enc_h_ri = ege.encrypt(self.public_key.g_a, h_ri)
            enc_g_ri = ege.encrypt(self.public_key.g_a, g_ri)
            nizk = NIZK(self.group)
            proof_1_1 = nizk.prove(
                enc_h_ri[2], enc_h_ri[0], tracker_voter_pair[0]
            )
            proof_1_2 = nizk.prove(
                enc_g_ri[2], enc_g_ri[0], tracker_voter_pair[0]
            )
            # print(nizk.verify(proof_1_1,enc_h_ri[0],tracker_voter_pair[0]))
            # print(nizk.verify(proof_1_2,enc_g_ri[0],tracker_voter_pair[0]))
            t = self.group.get_random()
            cpp = ChaumPedersenProof(self.group)

            enc_h_ri_t = {
                "c1": gmpy2.powmod(enc_h_ri[0], t, self.group.p),
                "c2": gmpy2.powmod(enc_h_ri[1], t, self.group.p),
            }
            enc_g_ri_t = {
                "c1": gmpy2.powmod(enc_g_ri[0], t, self.group.p),
                "c2": gmpy2.powmod(enc_g_ri[1], t, self.group.p),
            }

            proof_2_1 = cpp.prove_dleq(enc_g_ri[0], enc_g_ri[1], t)
            proof_2_2 = cpp.prove_dleq(enc_h_ri[0], enc_h_ri[1], t)
            proof_2_3 = cpp.prove_dleq(enc_g_ri[0], enc_h_ri[0], t)
            # print("delq21: "+str(cpp.verify_dleq(proof_2_1,enc_g_ri[0],enc_g_ri[1],enc_g_ri_t['c1'],enc_g_ri_t['c2'])))
            # print("delq22: "+str(cpp.verify_dleq(proof_2_2,enc_h_ri[0],enc_h_ri[1],enc_h_ri_t['c1'],enc_h_ri_t['c2'])))
            # print("delq23: "+str(cpp.verify_dleq(proof_2_3,enc_g_ri[0],enc_h_ri[0],enc_g_ri_t['c1'],enc_h_ri_t['c1'])))

            g_ri_t = gmpy2.powmod(g_ri, t, self.group.p)
            h_ri_t = gmpy2.powmod(h_ri, t, self.group.p)

            rhs_3_1 = gmpy2.divm(enc_g_ri[1], g_ri, self.group.p)
            rhs_3_1_t = gmpy2.divm(enc_g_ri_t["c2"], g_ri_t, self.group.p)

            rhs_3_2 = gmpy2.divm(enc_h_ri[1], h_ri, self.group.p)
            rhs_3_2_t = gmpy2.divm(enc_h_ri_t["c2"], h_ri_t, self.group.p)

            proof_3_1 = cpp.prove_dleq(enc_g_ri[0], rhs_3_1, t)
            # print("delq31: "+str(cpp.verify_dleq(proof_3_1,enc_g_ri[0],rhs_3_1,enc_g_ri_t['c1'],rhs_3_1_t)))

            proof_3_2 = cpp.prove_dleq(enc_g_ri[0], rhs_3_2, t)
            # print("delq32: "+str(cpp.verify_dleq(proof_3_2,enc_g_ri[0],rhs_3_2,enc_g_ri_t['c1'],rhs_3_2_t)))

            proof_4 = cpp.prove_dleq(g_ri, h_ri, t)
            # print("delq4: "+str(cpp.verify_dleq(proof_4,g_ri,h_ri,g_ri_t,h_ri_t)))

            proof_5 = nizk.prove(
                gmpy2.f_mod(gmpy2.mul(r_i, t), self.group.q),
                g_ri_t,
                tracker_voter_pair[0],
            )
            # print("nizk5: "+str(nizk.verify(proof_5,g_ri_t,tracker_voter_pair[0])))
            commitments.append(
                {
                    "id": tracker_voter_pair[0],
                    "enc_h_ri": enc_h_ri,
                    "enc_g_ri": enc_g_ri,
                    "r_i": r_i,
                    "p_1_1": proof_1_1,
                    "p_1_2": proof_1_2,
                    "p_2_1": proof_2_1,
                    "p_2_2": proof_2_2,
                    "p_2_3": proof_2_3,
                    "p_3_1": proof_3_1,
                    "p_3_2": proof_3_2,
                    "p_4": proof_4,
                    "p_5": proof_5,
                    "enc_h_ri_t": enc_h_ri_t,
                    "enc_g_ri_t": enc_g_ri_t,
                    "h_ri_t": h_ri_t,
                    "g_ri_t": g_ri_t,
                }
            )
            self.registry.append({"id": tracker_voter_pair[0], "g_ri": g_ri})
        return commitments

    def get_notification_entry(self, voter_id):
        for entry in self.registry:
            if entry["id"] == voter_id:
                return entry["g_ri"]

    def decrypt(group, registry_entry):
        ege = ElGamalEncryption(group)
        g_ri = group.raise_g(registry_entry["r_i"])
        ciphertext = ege.encrypt(registry_entry["ptk"], g_ri)
        return ciphertext


class ElectionAuthority:
    def __init__(self, group):
        self.group = group

    def generate_trackers(self, length, number):
        source = string.ascii_uppercase + string.digits
        trackers = []
        for i in range(number):
            trackers.append(
                "".join(random.choice(source) for j in range(length))
            )
        return trackers

    def raise_trackers(self, trackers):
        g_trackers = []
        for tracker in trackers:
            g_trackers.append(
                {
                    "tracker": tracker,
                    "g_tracker": self.group.raise_g(
                        self.group.hash_to_mpz(tracker)
                    ),
                }
            )
        return g_trackers

    def encrypt_trackers(self, public_key, trackers):
        encrypted_trackers = []
        ege = ElGamalEncryption(self.group)
        for tracker in trackers:
            encrypted_trackers.append(
                ege.encrypt(public_key, tracker["g_tracker"])
            )
        return encrypted_trackers
