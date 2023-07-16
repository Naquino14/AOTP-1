using System.Text;

namespace ADIS {
    public class AOTP1 {
        const int KEY_SIZE = 16;

        /// <summary>
        /// The current code string.
        /// </summary>
        /// 
        public string Code { get => GetCode(); }
        /// <summary>
        /// The current OTP.
        /// </summary>
        public byte[] OTP { get => GetOTP(); }

        private byte[] Key { get; init; }
        private long Epoch { get; init; }
        private int Duration { get; init; }

        /// <summary>
        /// Constructs a new AOTP using the specified parameters.
        /// </summary>
        /// <param name="key">The private key to be used in the HMAC.</param>
        /// <param name="epoch">The Unix timetamp epoch to be used.</param>
        /// <param name="duration">The duration of the OTP codes.</param>
        public AOTP1(byte[] key, long epoch, int duration) {
            this.Epoch = epoch;
            this.Duration = duration;
            Key = new byte[KEY_SIZE];
            for (int i = 0; i < KEY_SIZE; i++)
                this.Key[i] = key[i];
        }

        /// <summary>
        /// Gets the current code string.
        /// </summary>
        /// <returns>The code string.</returns>
        public string GetCode() => "NYI"; // TODO

        /// <summary>
        /// Gets the current OTP.
        /// </summary>
        /// <returns>The current OTP.</returns>
        public byte[] GetOTP() {
            var result = new byte[4]; // result is a word

            // step one is to get the counter value
            long t = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ct = (long)Math.Floor((double)(t - Epoch) / Duration);

            // step 2 compute the MAC using ACH1
            using var achmac0 = new ACH1(ACH1.InitType.bytes);
            using var achmac1 = new ACH1(ACH1.InitType.bytes);
            // create first and second pad
            var pad0 = new byte[32]; 
            var pad1 = new byte[32];
            for (int i = 0; i < 32; i++) {
                pad0[i] = 0b1010;
                pad1[i] = 0b0011;
            }
            // otp the key and pad
            OTPArray(pad0, Key);
            // append ct
            string ctString = ct.ToString();
            var padSum0 = new byte[pad0.Length + ctString.Length];
            Array.Copy(pad0, padSum0, pad0.Length);
            Array.Copy(Encoding.ASCII.GetBytes(ctString), 0, padSum0, pad0.Length, ctString.Length);
            // hash it
            var hash = achmac0.ComputeHash(padSum0);
            // condense it down to 32 bytes
            var sum = CompressDigest(hash);
            // create the second pad-key mix
            OTPArray(pad1, Key);
            // append the previous sum to the pad mix
            var padSum1 = new byte[64];
            Array.Copy(pad1, padSum1, pad1.Length);
            Array.Copy(sum, 0, padSum1, 32, sum.Length);

            hash = achmac1.ComputeHash(padSum1);
            sum = CompressDigest(hash);

            // TODO: select bits to form the final code
            Array.Copy(sum, result, 4);
            return result;
        }

        
        /// <summary>
        /// XOR a key into input.
        /// </summary>
        /// <param name="input">The input array to be modified.</param>
        /// <param name="key">The key to XOR into the input.</param>
        private static void OTPArray(byte[] input, byte[] key) {
            for (int i = 0; i < key.Length; i++)
                input[i] = (byte)(input[i] ^ key[i]);
        }
        
        /// <summary>
        /// Compresses 128 byte digest into itself 4 times.
        /// </summary>
        /// <param name="input">The input</param>
        /// <returns>The 32 byte digest</returns>
        private static byte[] CompressDigest(byte[] input) {
            var result = new byte[32];
            // otp the hash on itself
            for (int i = 0; i < 32; i++)
                result[i] = (byte)(input[i] ^ input[i + 32] ^ input[i + 64] ^ input[i + 96]);
            return result;
        }
    }
}
