using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MurmurHash
{
    public static class MurmurHash3
    {
        public const ulong C0 = 0xC6A4A7935BD1E995UL;
        public const ulong C1 = 0x87C37B91114253D5UL;
        public const ulong C2 = 0x4CF5AD432745937FUL;
        public const int BufferSize8 = 8;
        public const int BufferSize16 = 16;

        public struct State32
        {
            public uint x_;
            public long length_;
        }

        public class State64
        {
            public ulong h_;
            public long length_;
            public int remaining_;
            public byte[] buffer_ = new byte[BufferSize8];
        }

        public class State128
        {
            public ulong h1_;
            public ulong h2_;
            public long length_;
            public int remaining_;
            public byte[] buffer_ = new byte[BufferSize16];
        }

        #region 32bit
        /// <summary>
        /// Scrambling 32bit data
        /// </summary>
        /// <param name="x"></param>
        /// <returns>scrambled x</returns>
        public static uint Scramble(uint x)
        {
            x *= 0xCC9E2D51U;
            x = (x << 15) | (x >> 17);
            x *= 0x1B873593U;
            return x;
        }

        public static uint GetUint(byte[] buffer, long offset)
        {
            return ((uint)buffer[offset + 0] << 0) |
                   ((uint)buffer[offset + 1] << 8) |
                   ((uint)buffer[offset + 2] << 16) |
                   ((uint)buffer[offset + 3] << 24);
        }

        public static byte[] ComputeHash32(byte[] buffer)
        {
            State32 state = new State32();
            state = Update32(state, buffer, 0, buffer.LongLength);
            return Finalize32(state);
        }

        public static byte[] ComputeHash32(byte[] buffer, long offset, long length)
        {
            State32 state = new State32();
            state = Update32(state, buffer, offset, length);
            return Finalize32(state);
        }

        public static State32 Update32(State32 state, byte[] buffer)
        {
            return Update32(state, buffer, 0, buffer.LongLength);
        }

        public static State32 Update32(State32 state, byte[] buffer, long offset, long length)
        {
            uint h = state.x_;
            long len = (length >> 2) << 2;
            for (long i = 0; i < len; i += 4)
            {
                uint x = GetUint(buffer, i + offset);
                h ^= Scramble(x);
                h = (h << 13) | (h >> 19);
                h = h * 5 + 0xE6546B64U;
            }
            long remain = length - len;
            uint k = 0;
            for (long i = remain - 1; 0 <= i; --i)
            {
                k <<= 8;
                k |= buffer[offset + len + i];
            }

            h ^= Scramble(k);
            state.x_ = h;
            state.length_ += length;
            return state;
        }

        public static byte[] Finalize32(State32 state)
        {
            uint h = FinalizeRaw32(state);
            byte[] r = new byte[4];
            Reverse(r, h);
            return r;
        }

        public static uint FinalizeRaw32(State32 state)
        {
            uint h = state.x_;
            h ^= (uint)state.length_;
            h ^= h >> 16;
            h *= 0x85EBCA6B;
            h ^= h >> 13;
            h *= 0xC2B2AE35;
            h ^= h >> 16;
            return h;
        }
        #endregion

        #region 64bit
        public static byte[] ComputeHash64(byte[] buffer)
        {
            State64 state = new State64();
            Update64(state, buffer);
            return Finalize64(state);
        }

        public static byte[] ComputeHash64(byte[] buffer, long offset, long length)
        {
            State64 state = new State64();
            Update64(state, buffer, offset, length);
            return Finalize64(state);
        }

        public static void Update64(State64 state, byte[] buffer)
        {
            Update64(state, buffer, 0, buffer.LongLength);
        }

        public static void Scramble64(ref ulong h, ulong k)
        {
            k *= C0;
            k ^= k >> 47;
            k *= C0;

            h ^= k;
            h *= C0;
        }

        public static void Update64(State64 state, byte[] buffer, long offset, long length)
        {
            System.Diagnostics.Debug.Assert(buffer != null);
            ulong h1 = state.h_;
            long o = offset;
            long end = offset + length;
            while (o < end)
            {
                long l = end - o;
                long r = BufferSize8 - state.remaining_;
                if (l < r)
                {
                    System.Array.Copy(buffer, o, state.buffer_, state.remaining_, l);
                    state.remaining_ += (int)l;
                    System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize8);
                    break;
                }
                System.Array.Copy(buffer, o, state.buffer_, state.remaining_, r);
                o += r;
                System.Diagnostics.Debug.Assert(BufferSize8 == (state.remaining_ + (int)r));
                ulong k1 = ToUlong(state.buffer_, 0);
                Scramble64(ref h1, k1);
                state.remaining_ = 0;
            }
            state.h_ = h1;
            state.length_ += length;
        }

        public static byte[] ComputeHash64(System.IO.Stream stream)
        {
            State64 state = new State64();
            state = Update64(state, stream);
            return Finalize64(state);
        }

        public static State64 Update64(State64 state, System.IO.Stream stream)
        {
            System.Diagnostics.Debug.Assert(stream != null);
            System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize8);
            ulong h1 = state.h_;
            long length = 0;
            for (; ; )
            {
                int l = BufferSize8 - (int)state.remaining_;
                int readSize = stream.Read(state.buffer_, state.remaining_, l);
                state.remaining_ += readSize;
                length += readSize;
                if (BufferSize8 <= state.remaining_)
                {
                    ulong k1 = ToUlong(state.buffer_, 0);
                    Scramble64(ref h1, k1);
                    state.remaining_ = 0;
                }
                else
                {
                    System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize8);
                    break;
                }
            }

            state.h_ = h1;
            state.length_ += length;
            return state;
        }

        public static byte[] Finalize64(State64 state)
        {
            ulong h = FinalizeRaw64(state);
            byte[] ret = new byte[8];
            Reverse(ret, 0, h);
            return ret;
        }

        public static ulong FinalizeRaw64(State64 state)
        {
            ulong h = state.h_;

            if (0 < state.remaining_)
            {
                System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize8);
                switch (state.remaining_)
                {
                    case 7:
                        h ^= (ulong)state.buffer_[6] << 48;
                        goto case 6;
                    case 6:
                        h ^= (ulong)state.buffer_[5] << 40;
                        goto case 5;
                    case 5:
                        h ^= (ulong)state.buffer_[4] << 32;
                        goto case 4;
                    case 4:
                        h ^= (ulong)state.buffer_[3] << 24;
                        goto case 3;
                    case 3:
                        h ^= (ulong)state.buffer_[2] << 16;
                        goto case 2;
                    case 2:
                        h ^= (ulong)state.buffer_[1] << 8;
                        goto case 1;
                    case 1:
                        h ^= state.buffer_[0];
                        h *= C0;
                        break;
                }
            }

            h ^= h >> 47;
            h *= C0;
            h ^= h >> 47;
            return h;
        }
        #endregion

        #region 128bit
        public static byte[] ComputeHash128(byte[] buffer)
        {
            State128 state = new State128();
            Update128(state, buffer);
            return Finalize128(state);
        }

        public static byte[] ComputeHash128(byte[] buffer, long offset, long length)
        {
            State128 state = new State128();
            Update128(state, buffer, offset, length);
            return Finalize128(state);
        }

        public static void Update128(State128 state, byte[] buffer)
        {
            Update128(state, buffer, 0, buffer.LongLength);
        }

        public static void Scramble128(ref ulong h1, ref ulong h2, ulong k1, ulong k2)
        {
            k1 *= C1;
            k1 = (k1 << 31) | (k1 >> (64 - 31));
            k1 *= C2;
            h1 ^= k1;

            h1 = (h1 << 27) | (h1 >> (64 - 27));
            h1 += h2;
            h1 = h1 * 5 + 0x52dce729;

            k2 *= C2;
            k2 = (k2 << 33) | (k2 >> (64 - 33));
            k2 *= C1;
            h2 ^= k2;

            h2 = (h2 << 31) | (h2 >> (64 - 31));
            h2 += h1;
            h2 = h2 * 5 + 0x38495ab5;
        }

        public static void Update128(State128 state, byte[] buffer, long offset, long length)
        {
            System.Diagnostics.Debug.Assert(buffer != null);
            ulong h1 = state.h1_;
            ulong h2 = state.h2_;
            long o = offset;
            long end = offset + length;
            while (o < end)
            {
                long l = end - o;
                long r = BufferSize16 - state.remaining_;
                if (l < r)
                {
                    System.Array.Copy(buffer, o, state.buffer_, state.remaining_, l);
                    state.remaining_ += (int)l;
                    System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize16);
                    break;
                }
                System.Array.Copy(buffer, o, state.buffer_, state.remaining_, r);
                o += r;
                System.Diagnostics.Debug.Assert(BufferSize16 == (state.remaining_ + (int)r));
                ulong k1 = ToUlong(state.buffer_, 0);
                ulong k2 = ToUlong(state.buffer_, 8);
                Scramble128(ref h1, ref h2, k1, k2);
                state.remaining_ = 0;
            }
            state.h1_ = h1;
            state.h2_ = h2;
            state.length_ += length;
        }

        public static byte[] ComputeHash128(System.IO.Stream stream)
        {
            State128 state = new State128();
            state = Update128(state, stream);
            return Finalize128(state);
        }

        public static State128 Update128(State128 state, System.IO.Stream stream)
        {
            System.Diagnostics.Debug.Assert(stream != null);
            System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize16);
            ulong h1 = state.h1_;
            ulong h2 = state.h2_;
            long length = 0;
            for (; ; )
            {
                int l = BufferSize16 - (int)state.remaining_;
                int readSize = stream.Read(state.buffer_, state.remaining_, l);
                state.remaining_ += readSize;
                length += readSize;
                if (BufferSize16 <= state.remaining_)
                {
                    ulong k1 = ToUlong(state.buffer_, 0);
                    ulong k2 = ToUlong(state.buffer_, 8);
                    Scramble128(ref h1, ref h2, k1, k2);
                    state.remaining_ = 0;
                }
                else
                {
                    System.Diagnostics.Debug.Assert(state.remaining_ < BufferSize16);
                    break;
                }
            }

            state.h1_ = h1;
            state.h2_ = h2;
            state.length_ += length;
            return state;
        }

        public static byte[] Finalize128(State128 state)
        {
            (ulong h1, ulong h2) h = FinalizeRaw128(state);
            byte[] ret = new byte[16];
            Reverse(ret, 0, h.h1);
            Reverse(ret, 8, h.h2);
            return ret;
        }

        public static (ulong h1, ulong h2) FinalizeRaw128(State128 state)
        {
            ulong h1 = state.h1_;
            ulong h2 = state.h2_;

            if (0 < state.remaining_)
            {
                ulong k1 = 0;
                ulong k2 = 0;
                switch (state.remaining_)
                {
                    case 15:
                        k2 ^= (ulong)state.buffer_[14] << 48;
                        goto case 14;
                    case 14:
                        k2 ^= (ulong)state.buffer_[13] << 40;
                        goto case 13;
                    case 13:
                        k2 ^= (ulong)state.buffer_[12] << 32;
                        goto case 12;
                    case 12:
                        k2 ^= (ulong)state.buffer_[11] << 24;
                        goto case 11;
                    case 11:
                        k2 ^= (ulong)state.buffer_[10] << 16;
                        goto case 10;
                    case 10:
                        k2 ^= (ulong)state.buffer_[9] << 8;
                        goto case 9;
                    case 9:
                        k2 ^= state.buffer_[8];
                        k2 *= C2;
                        k2 = (k2 << 33) | (k2 >> (64 - 33));
                        k2 *= C1;
                        h2 ^= k2;
                        goto case 8;
                    case 8:
                        k1 ^= (ulong)state.buffer_[7] << 56;
                        goto case 7;
                    case 7:
                        k1 ^= (ulong)state.buffer_[6] << 48;
                        goto case 6;
                    case 6:
                        k1 ^= (ulong)state.buffer_[5] << 40;
                        goto case 5;
                    case 5:
                        k1 ^= (ulong)state.buffer_[4] << 32;
                        goto case 4;
                    case 4:
                        k1 ^= (ulong)state.buffer_[3] << 24;
                        goto case 3;
                    case 3:
                        k1 ^= (ulong)state.buffer_[2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (ulong)state.buffer_[1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= state.buffer_[0];
                        k1 *= C1;
                        k1 = (k1 << 31) | (k1 >> (64 - 31));
                        k1 *= C2;
                        h1 ^= k1;
                        break;
                }
            }

            // finalization
            h1 ^= (ulong)state.length_;
            h2 ^= (ulong)state.length_;

            h1 += h2;
            h2 += h1;

            h1 = Mix64(h1);
            h2 = Mix64(h2);

            h1 += h2;
            h2 += h1;

            return (h1, h2);
        }
        #endregion

        public static ulong ToUlong(byte[] buffer, int offset)
        {
            return ((ulong)buffer[offset + 0] << 0) |
                   ((ulong)buffer[offset + 1] << 8) |
                   ((ulong)buffer[offset + 2] << 16) |
                   ((ulong)buffer[offset + 3] << 24) |
                   ((ulong)buffer[offset + 4] << 32) |
                   ((ulong)buffer[offset + 5] << 40) |
                   ((ulong)buffer[offset + 6] << 48) |
                   ((ulong)buffer[offset + 7] << 56);
        }

        private static ulong Mix64(ulong k)
        {
            k ^= k >> 33;
            k *= 0xff51afd7ed558ccd;
            k ^= k >> 33;
            k *= 0xc4ceb9fe1a85ec53;
            k ^= k >> 33;
            return k;
        }

        private static void Reverse(byte[] bytes, uint value)
        {
            bytes[0] = (byte)((value & 0xFF000000U) >> 24);
            bytes[1] = (byte)((value & 0x00FF0000U) >> 16);
            bytes[2] = (byte)((value & 0x0000FF00U) >> 8);
            bytes[3] = (byte)((value & 0x000000FFU) >> 0);
        }

        private static void Reverse(byte[] bytes, int offset, ulong value)
        {
            bytes[offset + 0] = (byte)((value & 0xFF00000000000000UL) >> 56);
            bytes[offset + 1] = (byte)((value & 0x00FF000000000000UL) >> 48);
            bytes[offset + 2] = (byte)((value & 0x0000FF0000000000UL) >> 40);
            bytes[offset + 3] = (byte)((value & 0x000000FF00000000UL) >> 32);
            bytes[offset + 4] = (byte)((value & 0x00000000FF000000UL) >> 24);
            bytes[offset + 5] = (byte)((value & 0x0000000000FF0000UL) >> 16);
            bytes[offset + 6] = (byte)((value & 0x000000000000FF00UL) >> 8);
            bytes[offset + 7] = (byte)((value & 0x00000000000000FFUL) >> 0);
        }
    }
}
