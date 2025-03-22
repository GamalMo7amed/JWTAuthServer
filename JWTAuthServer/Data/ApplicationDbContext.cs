using JWTAuthServer.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthServer.Data
{
    public class ApplicationDbContext:DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
           : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<UserRole>()
               .HasKey(ur => new { ur.UserId, ur.RoleId });
            modelBuilder.Entity<UserRole>()
                .HasOne(u => u.User)
                .WithMany(u => u.UserRoles)
                .HasForeignKey(u => u.UserId);

            modelBuilder.Entity<UserRole>()
                .HasOne(ur => ur.Role)
                .WithMany(r => r.UserRoles)
                .HasForeignKey(ur => ur.RoleId);
            // Seed initial data for Roles, Users, Clients, and UserRoles.
            modelBuilder.Entity<Role>().HasData(
                new Role { Id = 1, Name = "Admin", Description = "Admin Role" },
                new Role { Id = 2, Name = "Editor", Description = " Editor Role" },
                new Role { Id = 3, Name = "User", Description = "User Role" }
            );
            modelBuilder.Entity<Client>().HasData(
                new Client
                {
                    Id = 1,
                    ClientId = "Client1",
                    Name = "Client Application 1",
                    ClientURL = "https://client1.com"
                },
                new Client
                {
                    Id = 2,
                    ClientId = "Client2",
                    Name = "Client Application 2",
                    ClientURL = "https://client2.com"
                }
            );
        }
        // DbSet representing the Users table.
        public DbSet<User> Users { get; set; }
        // DbSet representing the Roles table.
        public DbSet<Role> Roles { get; set; }
        // DbSet representing the Clients table.
        public DbSet<Client> Clients { get; set; }
        // DbSet representing the UserRoles join table.
        public DbSet<UserRole> UserRoles { get; set; }
        // DbSet representing the SigningKeys table.
        public DbSet<SigningKey> SigningKeys { get; set; }
    }
}
