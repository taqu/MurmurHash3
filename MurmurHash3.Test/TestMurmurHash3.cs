using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;

namespace MurmurHash.Test
{
    [TestClass]
    public class MurmurHash3Tests
    {
        private class TestCase
        {
            public string Value { get; set; }
            public string ExpectedHash { get; set; }
            public int Offset { get; set; }
            public int Length { get; set; }
        }

        private static readonly TestCase[] TestCases32 = new[]
        {
            new TestCase { Value = "", ExpectedHash = "00000000" },
            new TestCase { Value = "test", ExpectedHash = "ba6bd213" },
            new TestCase { Value = "Hello, world!", ExpectedHash = "c0363e43" },
            new TestCase { Value = "The quick brown fox jumps over the lazy dog", ExpectedHash = "2e4ff723" },
            new TestCase { Value = " test", Offset = 1, Length = 4, ExpectedHash = "ba6bd213" },
        };

        [TestMethod]
        public void TestComputeHash32()
        {
            foreach (TestCase c in TestCases32)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(c.Value);

                byte[] val;
                if (c.Offset == 0 && c.Length == 0)
                {
                    val = MurmurHash.MurmurHash3.ComputeHash32(bytes);
                }
                else
                {
                    val = MurmurHash.MurmurHash3.ComputeHash32(bytes, c.Offset, c.Length);
                }

                string result = ByteArrayToHexString(val);
                Assert.AreEqual(c.ExpectedHash, result, "'{0}' expected: {1} result: {2}", c.Value, c.ExpectedHash, result);
            }
        }

        private static readonly TestCase[] TestCases64 = new[]
        {
            new TestCase { Value = "", ExpectedHash = "0000000000000000" },
            new TestCase { Value = "test", ExpectedHash = "ba1dc49aa6cfea13" },
            new TestCase { Value = "testtesttesttest", ExpectedHash = "d8b66f8347b78557" },
            new TestCase { Value = "testtesttesttestt", ExpectedHash = "b4ed50033888683f" },
            new TestCase { Value = "Hello, world!", ExpectedHash = "ebed32cc94a1106b" },
            new TestCase { Value = "The quick brown fox jumps over the lazy dog", ExpectedHash = "e20efe4e4ed6a812" },
            new TestCase { Value = " test", Offset = 1, Length = 4, ExpectedHash = "ba1dc49aa6cfea13" },
        };

        [TestMethod]
        public void TestComputeHash64()
        {
            foreach (TestCase c in TestCases64)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(c.Value);

                byte[] val;
                if (c.Offset == 0 && c.Length == 0)
                {
                    val = MurmurHash.MurmurHash3.ComputeHash64(bytes);
                }
                else
                {
                    val = MurmurHash.MurmurHash3.ComputeHash64(bytes, c.Offset, c.Length);
                }

                string result = ByteArrayToHexString(val);
                Assert.AreEqual(c.ExpectedHash, result, "'{0}' expected: {1} result: {2}", c.Value, c.ExpectedHash, result);
            }
        }

        private static readonly TestCase[] TestCases128 = new[]
        {
            new TestCase { Value = "Home grown, grass fed, cage free", ExpectedHash = "0da3518798b74a774f344b82e2315ee0" },
            new TestCase { Value = "The quick brown fox jumps over the lazy dog.", ExpectedHash = "cd99481f9ee902c9695da1a38987b6e7" },
            new TestCase { Value = "", ExpectedHash = "00000000000000000000000000000000" },
            new TestCase { Value = "\0", ExpectedHash = "4610abe56eff5cb551622daa78f83583" },
            new TestCase { Value = "\0\0", ExpectedHash = "3044b81a706c5de818f96bcc37e8a35b" },
            new TestCase { Value = "hello", ExpectedHash = "cbd8a7b341bd9b025b1e906a48ae1d19" },
            new TestCase { Value = "hello\0", ExpectedHash = "084ad4bb6b86b133d402ea7a9c40497b" },
            new TestCase { Value = "hello, world", ExpectedHash = "342fac623a5ebc8e4cdcbc079642414d" },
            new TestCase { Value = "19 Jan 2038 at 3:14:07 AM", ExpectedHash = "b89e5988b737affc664fc2950231b2cb" },
            new TestCase { Value = "The quick brown fox jumps over the lazy dog...", Length = 44, ExpectedHash = "cd99481f9ee902c9695da1a38987b6e7" },
            new TestCase { Value = "  The quick brown fox jumps over the lazy dog.  ", Offset = 2, Length = 44, ExpectedHash = "cd99481f9ee902c9695da1a38987b6e7" },
            new TestCase { Value = "A", ExpectedHash = "035fc2b79a29b17a387df29c46dd9937" },
            new TestCase { Value = "AB", ExpectedHash = "4a75211b3ce4fd780cb062fcc6fd36f1" },
            new TestCase { Value = "ABC", ExpectedHash = "8dbe6477a2f82fde9e2bee4f1c5ba64a" },
            new TestCase { Value = "ABCD", ExpectedHash = "6b12f6cbbad52f195ed5fd4947123e73" },
            new TestCase { Value = "ABCDE", ExpectedHash = "e27529fd9cd6948d2a20972ff65c1afb" },
            new TestCase { Value = "ABCDEF", ExpectedHash = "9174e89a43db6790712240d438c0221b" },
            new TestCase { Value = "ABCDEFG", ExpectedHash = "38af65d501cb4e481108a50231c00291" },
            new TestCase { Value = "ABCDEFGH", ExpectedHash = "a3a725013dbddba86159afa610f16e6e" },
            new TestCase { Value = "ABCDEFGHI", ExpectedHash = "98966aa8e255c53bbf1c6a451d2a9dda" },
            new TestCase { Value = "ABCDEFGHIJ", ExpectedHash = "9859c195fbe27161c6e03b18fb1919ae" },
            new TestCase { Value = "ABCDEFGHIJK", ExpectedHash = "acdbbc62314e9672dbd3146fa77571a0" },
            new TestCase { Value = "ABCDEFGHIJKL", ExpectedHash = "ef9b9fad55dd1d7eb672e5b446bb933e" },
            new TestCase { Value = "ABCDEFGHIJKLM", ExpectedHash = "8a36b1a411d89d5427fe32cd385ba142" },
            new TestCase { Value = "ABCDEFGHIJKLMN", ExpectedHash = "251f5ca561d3c9dd8b9026152da68e1b" },
            new TestCase { Value = "ABCDEFGHIJKLMNO", ExpectedHash = "909232aad85d17662a9f32df8851107b" },
            new TestCase { Value = "ABCDEFGHIJKLMNOP", ExpectedHash = "67d1ccc2efd7ed8f1a19cf5db1beac91" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQ", ExpectedHash = "99f4886afd7ab21110f6c2f976ba0533" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQR", ExpectedHash = "5330c5bef53b49794bde6ebeeb936de9" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRS", ExpectedHash = "e8e78b387b679e9097f036a55bf9f0a3" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRST", ExpectedHash = "dd9a0b5cde565b5cb9a4b6178efec5ab" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRSTU", ExpectedHash = "540c208f064c8a0c62a48fc84d51d2aa" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRSTUV", ExpectedHash = "1ff2da33e738e457eac024a30cb65cc5" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRSTUVW", ExpectedHash = "0dbdb6e58b16f867341c1b4a18464c3a" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRSTUVWX", ExpectedHash = "15c9c335a854f29be459cca1e9d91ff9" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRSTUVWXY", ExpectedHash = "1f4fbb86134e416bae3eca2a132f8dba" },
            new TestCase { Value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", ExpectedHash = "65e611fed09fced7355e36e45b7fd9e4" },
        };

        [TestMethod]
        public void TestComputeHash128()
        {
            foreach (TestCase c in TestCases128)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(c.Value);

                byte[] val;
                if (c.Offset == 0 && c.Length == 0)
                {
                    val = MurmurHash.MurmurHash3.ComputeHash128(bytes);
                }
                else
                {
                    val = MurmurHash.MurmurHash3.ComputeHash128(bytes, c.Offset, c.Length);
                }

                string result = ByteArrayToHexString(val);
                Assert.AreEqual(c.ExpectedHash, result, "'{0}' expected: {1} result: {2}", c.Value, c.ExpectedHash, result);
            }
        }

        [TestMethod]
        public void TestComputeHashStream128()
        {
            foreach (TestCase c in TestCases128)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(c.Value);

                // Act
                byte[] val;
                if (c.Offset == 0 && c.Length == 0)
                {
                    System.IO.MemoryStream memory = new System.IO.MemoryStream(bytes);
                    val = MurmurHash.MurmurHash3.ComputeHash128(memory);
                }
                else
                {
                    System.IO.MemoryStream memory = new System.IO.MemoryStream(bytes, c.Offset, c.Length);
                    val = MurmurHash.MurmurHash3.ComputeHash128(memory);
                }

                // Assert
                string result = ByteArrayToHexString(val);
                Assert.AreEqual(c.ExpectedHash, result, "'{0}' expected: {1} result: {2}", c.Value, c.ExpectedHash, result);
            }
        }

        [TestMethod]
        public void TestComputeHashSeparate128()
        {
            foreach (TestCase c in TestCases128)
            {
                Random random = new Random(DateTime.Now.Millisecond);
                byte[] bytes = Encoding.UTF8.GetBytes(c.Value);

                // Act
                byte[] val;
                if (c.Offset == 0 && c.Length == 0)
                {
                    int mid = 0 < bytes.Length ? random.Next(1, bytes.Length) : 0;
                    MurmurHash.MurmurHash3.State128 state = new MurmurHash.MurmurHash3.State128();
                    MurmurHash.MurmurHash3.Update128(state, bytes, 0, mid);
                    MurmurHash.MurmurHash3.Update128(state, bytes, mid, bytes.Length - mid);
                    val = MurmurHash.MurmurHash3.Finalize128(state);
                }
                else
                {
                    int mid = random.Next(1, c.Length);
                    MurmurHash.MurmurHash3.State128 state = new MurmurHash.MurmurHash3.State128();
                    MurmurHash.MurmurHash3.Update128(state, bytes, c.Offset, mid);
                    MurmurHash.MurmurHash3.Update128(state, bytes, c.Offset + mid, c.Length - mid);
                    val = MurmurHash.MurmurHash3.Finalize128(state);
                }

                // Assert
                string result = ByteArrayToHexString(val);
                Assert.AreEqual(c.ExpectedHash, result, "'{0}' expected: {1} result: {2}", c.Value, c.ExpectedHash, result);
            }
        }

        [TestMethod]
        public void TestComputeHashStreamSeparate128()
        {
            foreach (TestCase c in TestCases128)
            {
                Random random = new Random(DateTime.Now.Millisecond);
                byte[] bytes = Encoding.UTF8.GetBytes(c.Value);

                // Act
                byte[] val;
                if (c.Offset == 0 && c.Length == 0)
                {
                    int mid = 0 < bytes.Length ? random.Next(1, bytes.Length) : 0;
                    MurmurHash.MurmurHash3.State128 state = new MurmurHash.MurmurHash3.State128();
                    using (System.IO.MemoryStream memory = new System.IO.MemoryStream(bytes, 0, mid))
                    {
                        MurmurHash.MurmurHash3.Update128(state, memory);
                    }
                    using (System.IO.MemoryStream memory = new System.IO.MemoryStream(bytes, mid, bytes.Length - mid))
                    {
                        MurmurHash.MurmurHash3.Update128(state, memory);
                    }
                    val = MurmurHash.MurmurHash3.Finalize128(state);
                }
                else
                {
                    int mid = random.Next(1, c.Length);
                    MurmurHash.MurmurHash3.State128 state = new MurmurHash.MurmurHash3.State128();
                    using (System.IO.MemoryStream memory = new System.IO.MemoryStream(bytes, c.Offset, mid))
                    {
                        MurmurHash.MurmurHash3.Update128(state, memory);
                    }
                    using (System.IO.MemoryStream memory = new System.IO.MemoryStream(bytes, c.Offset + mid, c.Length - mid))
                    {
                        MurmurHash.MurmurHash3.Update128(state, memory);
                    }
                    val = MurmurHash.MurmurHash3.Finalize128(state);
                }

                // Assert
                string result = ByteArrayToHexString(val);
                Assert.AreEqual(c.ExpectedHash, result, "'{0}' expected: {1} result: {2}", c.Value, c.ExpectedHash, result);
            }
        }

        private static string ByteArrayToHexString(byte[] bytes)
        {
            return string.Concat(Array.ConvertAll(bytes, x => x.ToString("x2")));
        }
    }
}
