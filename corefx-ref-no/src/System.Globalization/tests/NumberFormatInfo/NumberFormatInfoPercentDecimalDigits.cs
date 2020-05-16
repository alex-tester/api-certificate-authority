// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Globalization.Tests
{
    public class NumberFormatInfoPercentDecimalDigits
    {
        [Fact]
        public void PercentDecimalDigits_GetInvariantInfo_ReturnsExpected()
        {
            Assert.Equal(2, NumberFormatInfo.InvariantInfo.PercentDecimalDigits);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(99)]
        public void PercentDecimalDigits_Set_GetReturnsExpected(int newPercentDecimalDigits)
        {
            NumberFormatInfo format = new NumberFormatInfo();
            format.PercentDecimalDigits = newPercentDecimalDigits;
            Assert.Equal(newPercentDecimalDigits, format.PercentDecimalDigits);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(100)]
        public void PercentDecimalDigits_SetInvalid_ThrowsArgumentOutOfRangeException(int value)
        {
            var format = new NumberFormatInfo();
            AssertExtensions.Throws<ArgumentOutOfRangeException>("value", "PercentDecimalDigits", () => format.PercentDecimalDigits = value);
        }


        [Fact]
        public void PercentDecimalDigits_SetReadOnly_ThrowsInvalidOperationException()
        {
            Assert.Throws<InvalidOperationException>(() => NumberFormatInfo.InvariantInfo.PercentDecimalDigits = 1);
        }
    }
}
