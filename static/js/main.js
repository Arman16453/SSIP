// Form validation and dynamic form handling
document.addEventListener('DOMContentLoaded', function() {
    // Handle dynamic team member fields
    const addTeamMemberBtn = document.getElementById('add-team-member');
    if (addTeamMemberBtn) {
        addTeamMemberBtn.addEventListener('click', function() {
            const teamMembersContainer = document.getElementById('team-members-container');
            const memberCount = teamMembersContainer.children.length;
            
            const newMemberDiv = document.createElement('div');
            newMemberDiv.className = 'mb-3 team-member';
            newMemberDiv.innerHTML = `
                <div class="input-group">
                    <input type="text" name="team_members[]" class="form-control" placeholder="Team Member ${memberCount + 1}" required>
                    <button type="button" class="btn btn-danger remove-member">Remove</button>
                </div>
            `;
            
            teamMembersContainer.appendChild(newMemberDiv);
        });
    }

    // Handle remove team member
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('remove-member')) {
            e.target.closest('.team-member').remove();
        }
    });

    // Handle dynamic component fields
    const addComponentBtn = document.getElementById('add-component');
    if (addComponentBtn) {
        addComponentBtn.addEventListener('click', function() {
            const componentsContainer = document.getElementById('components-container');
            const componentCount = componentsContainer.children.length;
            
            const newComponentDiv = document.createElement('div');
            newComponentDiv.className = 'mb-3 component-item';
            newComponentDiv.innerHTML = `
                <div class="input-group">
                    <input type="text" name="components[]" class="form-control" placeholder="Component ${componentCount + 1}" required>
                    <input type="number" name="costs[]" class="form-control" placeholder="Cost" required>
                    <button type="button" class="btn btn-danger remove-component">Remove</button>
                </div>
            `;
            
            componentsContainer.appendChild(newComponentDiv);
        });
    }

    // Handle remove component
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('remove-component')) {
            e.target.closest('.component-item').remove();
            updateTotalCost();
        }
    });

    // Update total cost when component costs change
    document.addEventListener('input', function(e) {
        if (e.target.name === 'costs[]') {
            updateTotalCost();
        }
    });
});

// Calculate and update total cost
function updateTotalCost() {
    const costs = Array.from(document.getElementsByName('costs[]'))
        .map(input => parseFloat(input.value) || 0);
    const total = costs.reduce((sum, cost) => sum + cost, 0);
    const totalCostElement = document.getElementById('total-cost');
    if (totalCostElement) {
        totalCostElement.value = total.toFixed(2);
    }
}
