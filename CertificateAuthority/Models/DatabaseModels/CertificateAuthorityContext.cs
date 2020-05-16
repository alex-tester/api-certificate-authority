using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace CertificateAuthority.Models.DatabaseModels
{
    public partial class CertificateAuthorityContext : DbContext
    {
        public CertificateAuthorityContext()
        {
        }

        public CertificateAuthorityContext(DbContextOptions<CertificateAuthorityContext> options)
            : base(options)
        {
        }

        public virtual DbSet<IssuedCertificates> IssuedCertificates { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. See http://go.microsoft.com/fwlink/?LinkId=723263 for guidance on storing connection strings.
                optionsBuilder.UseSqlServer("Server=sql03.observicing.net;Database=CertificateAuthority;Trusted_Connection=true;");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<IssuedCertificates>(entity =>
            {
                entity.Property(e => e.Base64Pfx)
                    .IsRequired()
                    .IsUnicode(false);

                entity.Property(e => e.CertificateThumbprint)
                    .IsRequired()
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.FriendlyName)
                    .HasMaxLength(150)
                    .IsUnicode(false);

                entity.Property(e => e.IsIntermediateCa).HasColumnName("IsIntermediateCA");

                entity.Property(e => e.IsRootCa).HasColumnName("IsRootCA");

                entity.Property(e => e.PkSecret)
                    .HasMaxLength(150)
                    .IsUnicode(false);

                entity.Property(e => e.SerialNumber)
                    .IsRequired()
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.Subject)
                    .IsRequired()
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.ValidFrom).HasColumnType("datetime");

                entity.Property(e => e.ValidTo).HasColumnType("datetime");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
