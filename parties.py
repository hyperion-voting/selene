import random, string, hashlib


import threshold_crypto as tc
import gmpy2

from primitives import DSA, ElGamalEncryption, NIZK, ChaumPedersenProof
from exceptions import (
    InvalidSignatureException,
    InvalidProofException,
    InvalidWFNProofException,
)
from util import deserialize_ep, deserialize_pd, serialize_pd
from subroutines import Mixnet
from Crypto.PublicKey import ECC


class Voter:
    def __init__(self, curve, id, vote_min, vote_max):
        self.id = id
        self.vote_min = vote_min
        self.vote_max = vote_max
        self.curve = curve
        self.g_ri = ECC.EccPoint(0, 0, "P-256")

    def choose_vote_value(self):
        self.vote = random.randrange(self.vote_min, self.vote_max)

    def generate_dsa_keys(self):
        dsa = DSA(self.curve)
        self.secret_key, self.public_key = dsa.keygen()

    def generate_trapdoor_keypair(self):
        self.ege = ElGamalEncryption(self.curve)
        self.secret_trapdoor_key, self.public_trapdoor_key = self.ege.keygen()

    def generate_pok_trapdoor_keypair(self):
        nizk = NIZK(self.curve)
        self.pok_trapdoor_key = nizk.prove(
            self.secret_trapdoor_key, self.public_trapdoor_key, self.id
        )

    def encrypt_vote(self, teller_public_key):
        self.g_vote = self.curve.raise_p(int(self.vote))
        self.encrypted_vote = self.ege.encrypt(
            teller_public_key.Q, self.g_vote
        )

    def generate_wellformedness_proof(self, teller_public_key):
        encrypted_vote = {
            "c1": self.encrypted_vote[0],
            "c2": self.encrypted_vote[1],
        }
        r = self.encrypted_vote[2]
        chmp = ChaumPedersenProof(self.curve)
        self.wellformedness_proof = chmp.prove_or_n(
            encrypted_vote,
            r,
            teller_public_key.Q,
            self.vote_max,
            int(self.vote),
            self.id,
        )

    def sign_ballot(self):
        self.dsa = DSA(self.curve)
        hash = self.curve.hash_to_mpz(
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
        self.g_ri = self.g_ri + r_i_j

    def retrieve_tracker(self, beta_term):
        ege = ElGamalEncryption(self.curve)
        ciphertext = [self.g_ri, beta_term]
        self.tracker = ege.decrypt(self.secret_trapdoor_key, ciphertext)
        return self.tracker


class Teller:
    def __init__(self, curve, secret_key_share, public_key):
        self.curve = curve
        self.secret_key_share = secret_key_share
        self.public_key = public_key
        self.registry = []
        self.ege = ElGamalEncryption(self.curve)

    def generate_threshold_keys(k, num_tellers, tc_key_params):
        thresh_params = tc.ThresholdParameters(k, num_tellers)
        pub_key, key_shares = tc.create_public_key_and_shares_centralized(
            tc_key_params, thresh_params
        )
        return pub_key, key_shares

    def validate_ballot(curve, teller_public_key, ballot):
        dsa = DSA(curve)
        hash = curve.hash_to_mpz(
            str(ballot["ev"])
            + str(ballot["ptk"])
            + str(ballot["pi_1"])
            + str(ballot["pi_2"])
        )
        nizk = NIZK(curve)
        chmp = ChaumPedersenProof(curve)
        try:
            if not dsa.verify(ballot["spk"], ballot["sig"], hash):
                raise InvalidSignatureException(ballot["id"])
            if not nizk.verify(ballot["pi_1"], ballot["ptk"], ballot["id"]):
                raise InvalidProofException(ballot["id"])
            ciphertext = {"c1": ballot["ev"][0], "c2": ballot["ev"][1]}
            if not chmp.verify_or_n(
                ciphertext,
                teller_public_key.Q,
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
        prod_alpha = ECC.EccPoint(0, 0, "P-256")
        prod_partial_decryptions = ECC.EccPoint(0, 0, "P-256")
        alpha_terms = []
        for ciphertext in ciphertexts:
            index = ciphertext[0]
            alpha_terms.append(ciphertext[1][0])
            t = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(
                            str(tau) + str(ciphertext[1][0]) + str(index)
                        ).encode("UTF-8")
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )

            s_2 = ciphertexts[1][0] * t
            prod_alpha = prod_alpha + s_2
        for partial_decryption in partial_decryptions:
            prod_partial_decryptions = (
                prod_partial_decryptions + partial_decryption.v_y
            )
        u = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1)
                        + str(p_1)
                        + str(self.curve.get_pars().P)
                        + str(public_key_share)
                        + str(alpha_terms)
                        + str(partial_decryptions)
                    ).encode("UTF-8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )
        v_1 = self.curve.raise_p(w) + (public_key_share * u)
        v_2 = prod_alpha * w
        v_2 = v_2 + (prod_partial_decryptions * u)
        if (p_1 == v_1) and (p_2 == v_2):
            return 1
        return 0

    def mp_partial_decrypt_single(self, ciphertexts_in, q1, q2):
        tau = self.curve.get_random()
        r = self.curve.get_random()
        p_1 = self.curve.raise_p(r)
        comm_tau = hashlib.sha256(str(tau).encode("UTF-8")).hexdigest()
        output = []
        proof = []
        prod_alpha_1 = ECC.EccPoint(0, 0, "P-256")
        alpha_terms = []
        index = 0
        for ciphertext in ciphertexts_in:
            alpha = ciphertext["comm"]
            t = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau) + str(alpha) + str(index)).encode("UTF-8")
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )

            index = index + 1
            pd = self.ege.partial_decrypt(
                ECC.EccPoint(
                    ciphertext["comm"][0]["x"],
                    ciphertext["comm"][0]["y"],
                    ciphertext["comm"][0]["curve"],
                ),
                self.secret_key_share,
            )
            prod_alpha = prod_alpha + (deserialize_ep(alpha) * t)
            alpha_terms.append(alpha)
            temp = []

            temp.append(index)
            temp.append(serialize_pd(pd))

            output.append(temp)

        q1.put(output)

        p_2 = prod_alpha * r
        u = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1)
                        + str(p_2)
                        + str(self.curve.get_pars().P.x)
                        + str(self.curve.get_pars().P.y)
                        + str(self.curve.raise_p(self.secret_key_share.y))
                        + str(alpha_terms)
                        + str(output)
                    ).encode("UTF-8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )

        w = r - (u * self.secret_key_share.y)
        q2.put(
            {
                "p_1": tc.data._ecc_point_to_serializable(p_1),
                "p_2": tc.data._ecc_point_to_serializable(p_2),
                "w": w,
                "tau": tau,
            }
        )

    def mp_partial_decrypt(self, ciphertexts_in, q1, q2, q3):
        tau_1 = self.curve.get_random()
        tau_2 = self.curve.get_random()
        r_1 = self.curve.get_random()
        r_2 = self.curve.get_random()
        p_1_1 = self.curve.raise_p(r_1)
        p_2_1 = self.curve.raise_p(r_2)
        comm_tau_1 = hashlib.sha256(str(tau_1).encode("UTF-8")).hexdigest()
        comm_tau_2 = hashlib.sha256(str(tau_2).encode("UTF-8")).hexdigest()
        output = []
        output2 = []
        proof = []
        prod_alpha_1 = ECC.EccPoint(0, 0, "P-256")
        prod_alpha_2 = ECC.EccPoint(0, 0, "P-256")
        alpha_terms_1 = []
        alpha_terms_2 = []
        flag = 0
        for ciphertext in ciphertexts_in:
            index = ciphertext[0]
            alpha_1 = ciphertext[1][0]
            alpha_2 = ciphertext[2][0]
            t_1 = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau_1) + str(alpha_1) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )
            t_2 = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau_2) + str(alpha_2) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )

            pd_1 = self.ege.partial_decrypt(
                ECC.EccPoint(
                    ciphertext[1][0]["x"],
                    ciphertext[1][0]["y"],
                    ciphertext[1][0]["curve"],
                ),
                self.secret_key_share,
            )
            pd_2 = self.ege.partial_decrypt(
                ECC.EccPoint(
                    ciphertext[2][0]["x"],
                    ciphertext[2][0]["y"],
                    ciphertext[2][0]["curve"],
                ),
                self.secret_key_share,
            )
            if flag == 0:
                flag = 1
                prod_alpha_1 = deserialize_ep(alpha_1) * t_1

                prod_alpha_2 = deserialize_ep(alpha_2) * t_2

            else:
                prod_alpha_1 = prod_alpha_1 + (deserialize_ep(alpha_1) * t_1)

                prod_alpha_2 = prod_alpha_2 + (deserialize_ep(alpha_2) * t_2)

            alpha_terms_1.append(alpha_1)
            alpha_terms_2.append(alpha_2)
            temp = []

            temp.append(index)
            temp.append(serialize_pd(pd_1))

            output.append(temp)
            temp2 = []
            temp2.append(index)
            temp2.append(serialize_pd(pd_2))
            output2.append(temp2)
        q1.put(output)
        q2.put(output2)

        p_1_2 = prod_alpha_1 * r_1
        p_2_2 = prod_alpha_2 * r_2
        u_1 = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1_1)
                        + str(p_1_2)
                        + str(self.curve.get_pars().P.x)
                        + str(self.curve.get_pars().P.y)
                        + str(self.curve.raise_p(self.secret_key_share.y))
                        + str(alpha_terms_1)
                        + str(output)
                    ).encode("UTF-8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )

        u_2 = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_2_1)
                        + str(p_2_2)
                        + str(self.curve.get_pars().P.x)
                        + str(self.curve.get_pars().P.y)
                        + str(self.curve.raise_p(self.secret_key_share.y))
                        + str(alpha_terms_2)
                        + str(output2)
                    ).encode("UTF-8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )

        w_1 = r_1 - (u_1 * self.secret_key_share.y)
        w_2 = r_2 - (u_2 * self.secret_key_share.y)
        q3.put(
            {
                "p_1_1": tc.data._ecc_point_to_serializable(p_1_1),
                "p_1_2": tc.data._ecc_point_to_serializable(p_1_2),
                "p_2_1": tc.data._ecc_point_to_serializable(p_2_1),
                "p_2_2": tc.data._ecc_point_to_serializable(p_2_2),
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
            ciphertext = tc.EncryptedMessage(
                deserialize_ep(ct[col][0]), deserialize_ep(ct[col][1]), ""
            )

            result.append(
                [
                    index,
                    tc.data._ecc_point_to_serializable(
                        self.ege.threshold_decrypt(
                            item[1],
                            ciphertext,
                            tc.ThresholdParameters(2, 3),
                        )
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
            # p.close()
        decrypted = data

    def verify_proof_h_r(curve, teller_public_key, ballot):
        nizk = NIZK(curve)
        try:
            if not nizk.verify_2(
                ballot["h_r"],
                teller_public_key.Q,
                ballot["ptk"],
                ballot["proof_h_r"],
            ):
                raise InvalidProofException(ballot["id"])
        except Exception as e:
            print(e)

    def re_encryption_mix(self, list_0):
        mx = Mixnet(self.curve)
        proof = mx.re_encryption_mix(list_0, self.public_key.Q)
        return proof

    def verify_re_enc_mix(self, list_0, proof):
        mx = Mixnet(self.curve)
        return mx.verify_mix(
            self.public_key.Q,
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

    def re_encryption_mix_trackers(self, encrypted_trackers):
        mx = Mixnet(self.curve)
        proof = mx.mix_trackers(encrypted_trackers, self.public_key.Q)
        list_1 = proof[0]
        """
        mx.verify_mix_trackers(self.public_key.Q,
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
        )"""

        return list_1

    def generate_tracker_commitments(self, tracker_voter_pairs):
        commitments = []
        for tracker_voter_pair in tracker_voter_pairs:
            r_i = self.curve.get_random()
            h_ri = tracker_voter_pair[1] * r_i
            g_ri = self.curve.raise_p(r_i)
            ege = ElGamalEncryption(self.curve)
            enc_h_ri = ege.encrypt(self.public_key.Q, h_ri)
            enc_g_ri = ege.encrypt(self.public_key.Q, g_ri)
            nizk = NIZK(self.curve)
            proof_1_1 = nizk.prove(
                enc_h_ri[2], enc_h_ri[0], tracker_voter_pair[0]
            )
            proof_1_2 = nizk.prove(
                enc_g_ri[2], enc_g_ri[0], tracker_voter_pair[0]
            )
            # print(nizk.verify(proof_1_1,enc_h_ri[0],tracker_voter_pair[0]))
            # print(nizk.verify(proof_1_2,enc_g_ri[0],tracker_voter_pair[0]))
            t = self.curve.get_random()
            cpp = ChaumPedersenProof(self.curve)

            enc_h_ri_t = {"c1": (enc_h_ri[0] * t), "c2": (enc_h_ri[1] * t)}
            enc_g_ri_t = {
                "c1": (enc_g_ri[0] * t),
                "c2": (enc_g_ri[1] * t),
            }

            proof_2_1 = cpp.prove_dleq(enc_g_ri[0], enc_g_ri[1], t)
            proof_2_2 = cpp.prove_dleq(enc_h_ri[0], enc_h_ri[1], t)
            proof_2_3 = cpp.prove_dleq(enc_g_ri[0], enc_h_ri[0], t)
            # print("delq21: "+str(cpp.verify_dleq(proof_2_1,enc_g_ri[0],enc_g_ri[1],enc_g_ri_t['c1'],enc_g_ri_t['c2'])))
            # print("delq22: "+str(cpp.verify_dleq(proof_2_2,enc_h_ri[0],enc_h_ri[1],enc_h_ri_t['c1'],enc_h_ri_t['c2'])))
            # print("delq23: "+str(cpp.verify_dleq(proof_2_3,enc_g_ri[0],enc_h_ri[0],enc_g_ri_t['c1'],enc_h_ri_t['c1'])))

            g_ri_t = g_ri * t
            h_ri_t = h_ri * t

            rhs_3_1 = enc_g_ri[1] + (-g_ri)
            rhs_3_1_t = enc_g_ri_t["c2"] + (-g_ri_t)

            rhs_3_2 = enc_h_ri[1] + (-h_ri)
            rhs_3_2_t = enc_h_ri_t["c2"] + (-h_ri_t)

            proof_3_1 = cpp.prove_dleq(enc_g_ri[0], rhs_3_1, t)
            # print("delq31: "+str(cpp.verify_dleq(proof_3_1,enc_g_ri[0],rhs_3_1,enc_g_ri_t['c1'],rhs_3_1_t)))

            proof_3_2 = cpp.prove_dleq(enc_g_ri[0], rhs_3_2, t)
            # print("delq32: "+str(cpp.verify_dleq(proof_3_2,enc_g_ri[0],rhs_3_2,enc_g_ri_t['c1'],rhs_3_2_t)))

            proof_4 = cpp.prove_dleq(g_ri, h_ri, t)
            # print("delq4: "+str(cpp.verify_dleq(proof_4,g_ri,h_ri,g_ri_t,h_ri_t)))

            proof_5 = nizk.prove(
                (r_i * t),
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

    def decrypt(curve, registry_entry):
        ege = ElGamalEncryption(curve)
        g_ri = curve.raise_p(registry_entry["r_i"])
        ciphertext = ege.encrypt(registry_entry["ptk"], g_ri)
        return ciphertext


class ElectionAuthority:
    def __init__(self, curve):
        self.curve = curve

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
                    "g_tracker": self.curve.raise_p(
                        self.curve.hash_to_mpz(tracker)
                    ),
                }
            )
        return g_trackers

    def encrypt_trackers(self, public_key, trackers):
        encrypted_trackers = []
        ege = ElGamalEncryption(self.curve)
        for tracker in trackers:
            encrypted_trackers.append(
                ege.encrypt(public_key, tracker["g_tracker"])
            )
        return encrypted_trackers
